#include "logger.h"
#include "dbconnector.h"
#include "producerstatetable.h"
#include "tokenize.h"
#include "ipprefix.h"
#include "sflowmgr.h"
#include "exec.h"
#include "shellcmd.h"

using namespace std;
using namespace swss;

SflowMgr::SflowMgr(DBConnector *appDb, const std::vector<TableConnector>& tableNames) :
        Orch(tableNames),
        m_appSflowTable(appDb, APP_SFLOW_TABLE_NAME),
        m_appSflowSessionTable(appDb, APP_SFLOW_SESSION_TABLE_NAME)
{
    m_intfAllConf = true;
    m_gEnable = false;
}

void SflowMgr::readPortConfig()
{
    auto consumer_it = m_consumerMap.find(CFG_PORT_TABLE_NAME);
    if (consumer_it != m_consumerMap.end())
    {
        consumer_it->second->drain();
        SWSS_LOG_NOTICE("Port Configuration Read..");
    }
    else
    {
        SWSS_LOG_ERROR("Consumer object for PORT_TABLE not found");
    }
}

bool SflowMgr::isPortEnabled(const std::string& alias)
{
    /* Checks if the sflow is enabled on the port */
    auto it = m_sflowPortConfMap.find(alias);
    if (it == m_sflowPortConfMap.end())
    {
        return false;
    }
    bool local_admin = it->second.local_admin_cfg;
    bool status = it->second.admin == "up" ? true : false;
    return m_gEnable && (m_intfAllConf || (local_admin && status));
}

void SflowMgr::sflowHandleService(bool enable)
{
    stringstream cmd;
    string res;

    SWSS_LOG_ENTER();

    if (enable)
    {
        cmd << "service hsflowd restart";
    }
    else
    {
        cmd << "service hsflowd stop";
    }

    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
    }
    else
    {
        SWSS_LOG_NOTICE("Starting hsflowd service");
        SWSS_LOG_INFO("Command '%s' succeeded", cmd.str().c_str());
    }

}

void SflowMgr::sflowUpdatePortInfo(Consumer &consumer)
{
    auto it = consumer.m_toSync.begin();

    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;
        string key = kfvKey(t);
        string op = kfvOp(t);
        auto values = kfvFieldsValues(t);

        if (op == SET_COMMAND)
        {
            SflowPortInfo port_info;
            bool new_port = false;

            auto sflowPortConf = m_sflowPortConfMap.find(key);
            if (sflowPortConf == m_sflowPortConfMap.end())
            {
                new_port = true;
                port_info.local_rate_cfg = false;
                port_info.local_admin_cfg = false;
                port_info.speed = ERROR_SPEED;
                port_info.oper_speed = NA_SPEED;
                port_info.rate = "";
                port_info.admin = "";
                m_sflowPortConfMap[key] = port_info;
            }

            bool rate_update = false;
            string new_speed = ERROR_SPEED;
            for (auto i : values)
            {
                if (fvField(i) == "speed")
                {
                    new_speed = fvValue(i);
                }
            }
            if (m_sflowPortConfMap[key].speed != new_speed)
            {
                m_sflowPortConfMap[key].speed = new_speed;
                /* if oper_speed is set, no need to write to APP_DB */
                if (m_sflowPortConfMap[key].oper_speed == NA_SPEED)
                {
                    rate_update = true;
                }
            }

            if (isPortEnabled(key))
            {
                // If the Local rate conf is already present, dont't override it even though the speed is changed
                if (new_port || (rate_update && !m_sflowPortConfMap[key].local_rate_cfg))
                {
                    vector<FieldValueTuple> fvs;
                    sflowGetGlobalInfo(fvs, key);
                    m_appSflowSessionTable.set(key, fvs);
                }
            }
        }
        else if (op == DEL_COMMAND)
        {
            auto sflowPortConf = m_sflowPortConfMap.find(key);
            if (sflowPortConf != m_sflowPortConfMap.end())
            {
                bool local_cfg = m_sflowPortConfMap[key].local_rate_cfg ||
                                 m_sflowPortConfMap[key].local_admin_cfg;

                m_sflowPortConfMap.erase(key);
                if ((m_intfAllConf && m_gEnable) || local_cfg)
                {
                    m_appSflowSessionTable.del(key);
                }
            }
        }
        it = consumer.m_toSync.erase(it);
    }
}

void SflowMgr::sflowProcessOperSpeed(Consumer &consumer)
{
    auto it = consumer.m_toSync.begin();

    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;
        string alias = kfvKey(t);
        string op = kfvOp(t);
        auto values = kfvFieldsValues(t);
        string oper_speed = "";
        bool rate_update = false;

        for (auto i : values)
        {
            if (fvField(i) == "speed")
            {
                oper_speed = fvValue(i);
            }
        }

        if (m_sflowPortConfMap.find(alias) != m_sflowPortConfMap.end() && op == SET_COMMAND)
        {
            SWSS_LOG_DEBUG("STATE_DB update: iface: %s, oper_speed: %s, cfg_speed: %s, new_speed: %s",
                            alias.c_str(), m_sflowPortConfMap[alias].oper_speed.c_str(),
                            m_sflowPortConfMap[alias].speed.c_str(),
                            oper_speed.c_str());
            /* oper_speed is updated by orchagent if the vendor supports and oper status is up */
            if (m_sflowPortConfMap[alias].oper_speed != oper_speed && !oper_speed.empty())
            {
                rate_update = true;
                if (oper_speed == m_sflowPortConfMap[alias].speed && m_sflowPortConfMap[alias].oper_speed == NA_SPEED)
                {
                    /* if oper_speed is equal to cfg_speed, avoid the write to APP_DB
                       Can happen if auto-neg is not set */
                    rate_update = false;
                }
                m_sflowPortConfMap[alias].oper_speed = oper_speed;
            }

            if (isPortEnabled(alias) && rate_update && !m_sflowPortConfMap[alias].local_rate_cfg)
            {
                auto rate = findSamplingRate(alias);
                FieldValueTuple fv("sample_rate", rate);
                vector<FieldValueTuple> fvs = {fv};
                m_appSflowSessionTable.set(alias, fvs);
                SWSS_LOG_NOTICE("Default sampling rate for %s updated to %s", alias.c_str(), rate.c_str());
            }
        }
        /* Do nothing for DEL as the SflowPortConfMap will already be cleared by the DEL from CONFIG_DB */ 
        it = consumer.m_toSync.erase(it);
    }
}

void SflowMgr::sflowHandleSessionAll(bool enable)
{
    for (auto it: m_sflowPortConfMap)
    {
        if (enable)
        {
            vector<FieldValueTuple> fvs;
            if (it.second.local_rate_cfg || it.second.local_admin_cfg)
            {
                sflowGetPortInfo(fvs, it.second);
                /* Use global admin state if there is not a local one */
                if (!it.second.local_admin_cfg) {
                    FieldValueTuple fv1("admin_state", "up");
                    fvs.push_back(fv1);
                }
            }
            else
            {
                sflowGetGlobalInfo(fvs, it.first);
            }
            m_appSflowSessionTable.set(it.first, fvs);
        }
        else if (!it.second.local_admin_cfg)
        {
            m_appSflowSessionTable.del(it.first);
        }
    }
}

void SflowMgr::sflowHandleSessionLocal(bool enable)
{
    for (auto it: m_sflowPortConfMap)
    {
        if (it.second.local_admin_cfg || it.second.local_rate_cfg)
        {
            vector<FieldValueTuple> fvs;
            sflowGetPortInfo(fvs, it.second);
            if (enable)
            {
                m_appSflowSessionTable.set(it.first, fvs);
            }
            else
            {
                m_appSflowSessionTable.del(it.first);
            }
        }
    }
}

void SflowMgr::sflowGetGlobalInfo(vector<FieldValueTuple> &fvs, const string& alias)
{
    FieldValueTuple fv1("admin_state", "up");
    fvs.push_back(fv1);

    FieldValueTuple fv2("sample_rate", findSamplingRate(alias));
    fvs.push_back(fv2);
}

void SflowMgr::sflowGetPortInfo(vector<FieldValueTuple> &fvs, SflowPortInfo &local_info)
{
    if (local_info.local_admin_cfg)
    {
        FieldValueTuple fv1("admin_state", local_info.admin);
        fvs.push_back(fv1);
    }

    FieldValueTuple fv2("sample_rate", local_info.rate);
    fvs.push_back(fv2);
}

void SflowMgr::sflowCheckAndFillValues(string alias, vector<FieldValueTuple> &values,
                                       vector<FieldValueTuple> &fvs)
{
    string rate;
    bool admin_present = false;
    bool rate_present = false;

    for (auto i : values)
    {
        if (fvField(i) == "sample_rate")
        {
            rate_present = true;
            m_sflowPortConfMap[alias].rate = fvValue(i);
            m_sflowPortConfMap[alias].local_rate_cfg = true;
            FieldValueTuple fv(fvField(i), fvValue(i));
            fvs.push_back(fv);
        }
        if (fvField(i) == "admin_state")
        {
            admin_present = true;
            m_sflowPortConfMap[alias].admin = fvValue(i);
            m_sflowPortConfMap[alias].local_admin_cfg = true;
            FieldValueTuple fv(fvField(i), fvValue(i));
            fvs.push_back(fv);
        }
        if (fvField(i) == "NULL")
        {
            continue;
        }
    }

    if (!rate_present)
    {
        /* Go back to default sample-rate if there is not existing rate OR
         * if a local config has been done but the rate has been removed
         */
        if (m_sflowPortConfMap[alias].rate == "" ||
            m_sflowPortConfMap[alias].local_rate_cfg)
        {
            m_sflowPortConfMap[alias].rate = findSamplingRate(alias);
        }
        m_sflowPortConfMap[alias].local_rate_cfg = false;
        FieldValueTuple fv("sample_rate", m_sflowPortConfMap[alias].rate);
        fvs.push_back(fv);
    }

    if (!admin_present)
    {
        if (m_sflowPortConfMap[alias].admin == "")
        {
            /* By default admin state is enabled if not set explicitly */
            m_sflowPortConfMap[alias].admin = "up";
        }
        m_sflowPortConfMap[alias].local_admin_cfg = false;
        FieldValueTuple fv("admin_state", m_sflowPortConfMap[alias].admin);
        fvs.push_back(fv);
    }
}

string SflowMgr::findSamplingRate(const string& alias)
{
    /* Default sampling rate is equal to the oper_speed, if present. 
        if oper_speed is not found, use the configured speed */
    if (m_sflowPortConfMap.find(alias) == m_sflowPortConfMap.end())
    {
        SWSS_LOG_ERROR("%s not found in port configuration map", alias.c_str());
        return ERROR_SPEED;
    }
    string oper_speed = m_sflowPortConfMap[alias].oper_speed;
    string cfg_speed = m_sflowPortConfMap[alias].speed;
    if (!oper_speed.empty() && oper_speed != NA_SPEED)
    {
        return oper_speed;
    }
    return cfg_speed;
}

void SflowMgr::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    auto table = consumer.getTableName();

    if (table == CFG_PORT_TABLE_NAME)
    {
        sflowUpdatePortInfo(consumer);
        return;
    }
    else if (table == STATE_PORT_TABLE_NAME)
    {
        sflowProcessOperSpeed(consumer);
        return;
    }

    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;

        string key = kfvKey(t);
        string op = kfvOp(t);
        auto values = kfvFieldsValues(t);

        if (op == SET_COMMAND)
        {
            if (table == CFG_SFLOW_TABLE_NAME)
            {
                for (auto i : values)
                {
                    if (fvField(i) == "admin_state")
                    {
                        bool enable = false;
                        if (fvValue(i) == "up")
                        {
                            enable = true;
                        }
                        if (enable == m_gEnable)
                        {
                            break;
                        }
                        m_gEnable = enable;
                        sflowHandleService(enable);
                        if (m_intfAllConf)
                        {
                            sflowHandleSessionAll(enable);
                        }
                        sflowHandleSessionLocal(enable);
                    }
                }
                m_appSflowTable.set(key, values);
            }
            else if (table == CFG_SFLOW_SESSION_TABLE_NAME)
            {
                if (key == "all")
                {
                    for (auto i : values)
                    {
                        if (fvField(i) == "admin_state")
                        {
                            bool enable = false;

                            if (fvValue(i) == "up")
                            {
                                enable = true;
                            }
                            if ((enable != m_intfAllConf) && (m_gEnable))
                            {
                                sflowHandleSessionAll(enable);
                            }
                            m_intfAllConf = enable;
                        }
                    }
                }
                else
                {
                    auto sflowPortConf = m_sflowPortConfMap.find(key);

                    if (sflowPortConf == m_sflowPortConfMap.end())
                    {
                        it++;
                        continue;
                    }
                    vector<FieldValueTuple> fvs;
                    sflowCheckAndFillValues(key, values, fvs);
                    if (m_gEnable)
                    {
                        m_appSflowSessionTable.set(key, fvs);
                    }
                }
            }
        }
        else if (op == DEL_COMMAND)
        {
            if (table == CFG_SFLOW_TABLE_NAME)
            {
                if (m_gEnable)
                {
                    sflowHandleService(false);
                    sflowHandleSessionAll(false);
                    sflowHandleSessionLocal(false);
                }
                m_gEnable = false;
                m_appSflowTable.del(key);
            }
            else if (table == CFG_SFLOW_SESSION_TABLE_NAME)
            {
                if (key == "all")
                {
                    if (!m_intfAllConf)
                    {
                        if (m_gEnable)
                        {
                            sflowHandleSessionAll(true);
                        }
                    }
                    m_intfAllConf = true;
                }
                else
                {
                    m_appSflowSessionTable.del(key);
                    m_sflowPortConfMap[key].local_rate_cfg = false;
                    m_sflowPortConfMap[key].local_admin_cfg = false;
                    m_sflowPortConfMap[key].rate = "";
                    m_sflowPortConfMap[key].admin = "";

                    /* If Global configured, set global session on port after local config is deleted */
                    if (m_intfAllConf)
                    {
                        vector<FieldValueTuple> fvs;
                        sflowGetGlobalInfo(fvs, key);
                        m_appSflowSessionTable.set(key,fvs);
                    }
                }
            }
        }
        it = consumer.m_toSync.erase(it);
    }
}
