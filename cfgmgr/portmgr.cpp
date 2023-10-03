#include "logger.h"
#include "dbconnector.h"
#include "producerstatetable.h"
#include "tokenize.h"
#include "ipprefix.h"
#include "portmgr.h"
#include "exec.h"
#include "shellcmd.h"
#include <swss/redisutility.h>

using namespace std;
using namespace swss;

PortMgr::PortMgr(DBConnector *cfgDb, DBConnector *appDb, DBConnector *stateDb, const vector<string> &tableNames) :
        Orch(cfgDb, tableNames),
        m_cfgPortTable(cfgDb, CFG_PORT_TABLE_NAME),
        m_cfgSendToIngressPortTable(cfgDb, CFG_SEND_TO_INGRESS_PORT_TABLE_NAME),
        m_cfgLagMemberTable(cfgDb, CFG_LAG_MEMBER_TABLE_NAME),
        m_statePortTable(stateDb, STATE_PORT_TABLE_NAME),
        m_appSendToIngressPortTable(appDb, APP_SEND_TO_INGRESS_PORT_TABLE_NAME),
        m_appPortTable(appDb, APP_PORT_TABLE_NAME)
{
}

bool PortMgr::setPortMtu(const string &alias, const string &mtu)
{
    stringstream cmd;
    string res, cmd_str;

    // ip link set dev <port_name> mtu <mtu>
    cmd << IP_CMD << " link set dev " << shellquote(alias) << " mtu " << shellquote(mtu);
    cmd_str = cmd.str();
    int ret = swss::exec(cmd_str, res);
    if (!ret)
    {
        // Set the port MTU in application database to update both
        // the port MTU and possibly the port based router interface MTU
        return writeConfigToAppDb(alias, "mtu", mtu);
    }
    else if (!isPortStateOk(alias))
    {
        // Can happen when a DEL notification is sent by portmgrd immediately followed by a new SET notif
        SWSS_LOG_WARN("Setting mtu to alias:%s netdev failed with cmd:%s, rc:%d, error:%s", alias.c_str(), cmd_str.c_str(), ret, res.c_str());
        return false;
    }
    else
    {
        throw runtime_error(cmd_str + " : " + res);
    }
    vector<FieldValueTuple> temp;

    /* 'mtu_slowpath' has higher priority than 'mtu' for the netdev mtu in kernel */
    if (m_cfgPortTable.get(alias, temp))
    {
        auto mtu_slowpath = swss::fvsGetValue(temp, "mtu_slowpath", true);
        if (!mtu_slowpath)
        {
            // ip link set dev <port_name> mtu <mtu>
            cmd << IP_CMD << " link set dev " << shellquote(alias) << " mtu " << shellquote(mtu);
            EXEC_WITH_ERROR_THROW(cmd.str(), res);

        }
    }

    // Set the port MTU in application database to update both
    // the port MTU and possibly the port based router interface MTU
    vector<FieldValueTuple> fvs;
    FieldValueTuple fv("mtu", mtu);
    fvs.push_back(fv);
    m_appPortTable.set(alias, fvs);

    return true;
}

bool PortMgr::setPortMtuSlowpath(const string &alias, const string &mtu_slowpath)
{
    /* 'mtu_slowpath' will only configure the netdev mtu in kernel, and has higher priority than 'mtu' attr
     */
    stringstream cmd;
    string res;
    int ret;

    SWSS_LOG_NOTICE("set mtu_slowpath netdev %s %s",
                        alias.c_str(), mtu_slowpath.c_str());

    // ip link set dev <port_name> mtu <mtu>
    cmd << IP_CMD << " link set dev " << shellquote(alias) << " mtu " << shellquote(mtu_slowpath);
    ret = swss::exec(cmd.str(), res);

    if (ret)
    {
        SWSS_LOG_WARN("Failed to set mtu_slowpath to %s netdev with cmd:%s, rc:%d, error:%s",
                        alias.c_str(), cmd.str().c_str(), ret, res.c_str());
    }

    return (ret == 0);
}



bool PortMgr::setPortAdminStatus(const string &alias, const bool up)
{
    stringstream cmd;
    string res, cmd_str;

    // ip link set dev <port_name> [up|down]
    cmd << IP_CMD << " link set dev " << shellquote(alias) << (up ? " up" : " down");
    cmd_str = cmd.str();
    int ret = swss::exec(cmd_str, res);
    if (!ret)
    {
        return writeConfigToAppDb(alias, "admin_status", (up ? "up" : "down"));
    }
    else if (!isPortStateOk(alias))
    {
        // Can happen when a DEL notification is sent by portmgrd immediately followed by a new SET notification
        SWSS_LOG_WARN("Setting admin_status to alias:%s netdev failed with cmd%s, rc:%d, error:%s", alias.c_str(), cmd_str.c_str(), ret, res.c_str());
        return false;
    }
    else
    {
        throw runtime_error(cmd_str + " : " + res);
    }
    return true;
}

bool PortMgr::isPortStateOk(const string &alias)
{
    vector<FieldValueTuple> temp;

    if (m_statePortTable.get(alias, temp))
    {
        auto state_opt = swss::fvsGetValue(temp, "state", true);
        if (!state_opt)
        {
            return false;
        }

        SWSS_LOG_INFO("Port %s is ready", alias.c_str());
        return true;
    }

    return false;
}

void PortMgr::doSendToIngressPortTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();
    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;

        string alias = kfvKey(t);
        string op = kfvOp(t);
        auto fvs = kfvFieldsValues(t);

        if (op == SET_COMMAND)
        {
            SWSS_LOG_NOTICE("Add SendToIngress Port: %s",
                            alias.c_str());
            m_appSendToIngressPortTable.set(alias, fvs);
        }
        else if (op == DEL_COMMAND)
        {
            SWSS_LOG_NOTICE("Removing SendToIngress Port: %s",
                                alias.c_str());
            m_appSendToIngressPortTable.del(alias);
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation type %s", op.c_str());
        }
        it = consumer.m_toSync.erase(it);
    }

}

void PortMgr::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    auto table = consumer.getTableName();
    if (table == CFG_SEND_TO_INGRESS_PORT_TABLE_NAME)
    {
        doSendToIngressPortTask(consumer);
        return;
    }

    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;

        string alias = kfvKey(t);
        string op = kfvOp(t);

        if (op == SET_COMMAND)
        {
            /* portOk=true indicates that the port has been created in kernel.
             * We should not call any ip command if portOk=false. However, it is
             * valid to put port configuration to APP DB which will trigger port creation in kernel.
             */
            bool portOk = isPortStateOk(alias);

            string admin_status, mtu;
            std::vector<FieldValueTuple> field_values;
            string mtu_slowpath = "";

            bool configured = (m_portList.find(alias) != m_portList.end());

            /* If this is the first time we set port settings
             * assign default admin status and mtu
             */
            if (!configured)
            {
                admin_status = DEFAULT_ADMIN_STATUS_STR;
                mtu = DEFAULT_MTU_STR;

                m_portList.insert(alias);
            }
            else if (!portOk)
            {
                it++;
                continue;
            }

            for (auto i : kfvFieldsValues(t))
            {
                if (fvField(i) == "mtu")
                {
                    mtu = fvValue(i);
                }
                else if (fvField(i) == "admin_status")
                {
                    admin_status = fvValue(i);
                }
                else if (fvField(i) == "mtu_slowpath")
                {
                    mtu_slowpath = fvValue(i);
                }
                else
                {
                    field_values.emplace_back(i);
                }
            }

            if (field_values.size())
            {
                writeConfigToAppDb(alias, field_values);
            }

            if (!portOk)
            {
                SWSS_LOG_INFO("Port %s is not ready, pending...", alias.c_str());

                writeConfigToAppDb(alias, "mtu", mtu);
                writeConfigToAppDb(alias, "admin_status", admin_status);
                /* Retry setting these params after the netdev is created */
                field_values.clear();
                field_values.emplace_back("mtu", mtu);
                field_values.emplace_back("admin_status", admin_status);
                it->second = KeyOpFieldsValuesTuple{alias, SET_COMMAND, field_values};
                it++;
                continue;
            }

            if (!mtu.empty())
            {
                setPortMtu(alias, mtu);
                SWSS_LOG_NOTICE("Configure %s MTU to %s", alias.c_str(), mtu.c_str());
            }

            if (!mtu_slowpath.empty())
            {
                setPortMtuSlowpath(alias, mtu_slowpath);
                SWSS_LOG_NOTICE("Configure %s slowpath MTU to %s", alias.c_str(), mtu_slowpath.c_str());
            }

            if (!admin_status.empty())
            {
                setPortAdminStatus(alias, admin_status == "up");
                SWSS_LOG_NOTICE("Configure %s admin status to %s", alias.c_str(), admin_status.c_str());
            }
        }
        else if (op == DEL_COMMAND)
        {
            SWSS_LOG_NOTICE("Delete Port: %s", alias.c_str());
            m_appPortTable.del(alias);
            m_portList.erase(alias);
        }

        it = consumer.m_toSync.erase(it);
    }
}

bool PortMgr::writeConfigToAppDb(const std::string &alias, const std::string &field, const std::string &value)
{
    vector<FieldValueTuple> fvs;
    FieldValueTuple fv(field, value);
    fvs.push_back(fv);
    m_appPortTable.set(alias, fvs);

    return true;
}

bool PortMgr::writeConfigToAppDb(const std::string &alias, std::vector<FieldValueTuple> &field_values)
{
    m_appPortTable.set(alias, field_values);
    return true;
}
