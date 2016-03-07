#include "lagorch.h"

#include "logger.h"

#include "assert.h"

extern sai_lag_api_t*           sai_lag_api;

void LagOrch::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    if (consumer.m_toSync.empty())
        return;

    if (!m_portsOrch->isInitDone())
        return;

    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;

        string key = kfvKey(t);
        size_t found = key.find(':');
        string lag_alias, port_alias;
        if (found == string::npos)
            lag_alias = key;
        else
        {
            lag_alias = key.substr(0, found);
            port_alias = key.substr(found+1);
        }

        string op = kfvOp(t);

        /* Manipulate LAG when port_alias is empty */
        if (port_alias == "")
        {
            if (op == SET_COMMAND)
            {
                /* Duplicate entry */
                if (m_lags.find(lag_alias) != m_lags.end())
                {
                    SWSS_LOG_ERROR("Duplicate LAG entry alias:%s", lag_alias.c_str());
                    it = consumer.m_toSync.erase(it);
                    continue;
                }

                if (addLag(lag_alias))
                    it = consumer.m_toSync.erase(it);
                else
                    it++;
            }
            else if (op == DEL_COMMAND)
            {
                assert(m_lags.find(lag_alias) != m_lags.end());
                Port lag;
                assert(m_portsOrch->getPort(lag_alias, lag));

                if (removeLag(lag))
                    it = consumer.m_toSync.erase(it);
                else
                    it++;
            }
            else
            {
                SWSS_LOG_ERROR("Unknown operation type %s\n", op.c_str());
                it = consumer.m_toSync.erase(it);
            }
        }
        /* Manipulate member */
        else
        {
            assert(m_lags.find(lag_alias) != m_lags.end());
            Port lag, port;
            assert(m_portsOrch->getPort(lag_alias, lag));
            assert(m_portsOrch->getPort(port_alias, port));

            if (op == SET_COMMAND)
            {
                /* Duplicate entry */
                if (m_lags[lag_alias].find(port_alias) != m_lags[lag_alias].end())
                {
                    SWSS_LOG_ERROR("Duplicate LAG member entry lag:%s port:%s",
                            lag_alias.c_str(), port_alias.c_str());
                    it = consumer.m_toSync.erase(it);
                    continue;
                }

                assert(port.m_type == Port::PHY_PORT);

                if (addLagMember(lag, port))
                    it = consumer.m_toSync.erase(it);
                else
                    it++;
            }
            else if (op == DEL_COMMAND)
            {
                assert(m_lags[lag_alias].find(port_alias) != m_lags[lag_alias].end());
                assert(port.m_type == Port::LAG_MEMBER);

                if (removeLagMember(lag, port))
                    it = consumer.m_toSync.erase(it);
                else
                    it++;
            }
            else
            {
                SWSS_LOG_ERROR("Unknown operation type %s\n", op.c_str());
                it = consumer.m_toSync.erase(it);
            }
        }
    }
}

bool LagOrch::addLag(string lag)
{
    sai_object_id_t lag_id;
    sai_status_t status = sai_lag_api->create_lag(&lag_id, 0, NULL);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create LAG %s lid:%llx", lag.c_str(), lag_id);
        return false;
    }

    SWSS_LOG_ERROR("Create an empty LAG %s lid:%llx", lag.c_str(), lag_id);

    Port p(lag, Port::LAG);
    p.m_lag_id = lag_id;
    m_portsOrch->setPort(lag, p);

    m_lags[lag] = set<string>();

    return true;
}

bool LagOrch::removeLag(Port lag)
{
    /* Retry when the LAG still has members */
    if (m_lags[lag.m_alias].size() > 0)
    {
        SWSS_LOG_ERROR("Failed to remove non-empty LAG %s", lag.m_alias.c_str());
        return false;
    }

    sai_status_t status = sai_lag_api->remove_lag(lag.m_lag_id);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to remove LAG %s lid:%llx\n", lag.m_alias.c_str(), lag.m_lag_id);
        return false;
    }

    SWSS_LOG_ERROR("Remove LAG %s lid:%llx\n", lag.m_alias.c_str(), lag.m_lag_id);

    m_lags.erase(lag.m_alias);
    m_portsOrch->removePort(lag.m_alias);

    return true;
}

bool LagOrch::addLagMember(Port lag, Port port)
{
    sai_attribute_t attr;
    vector<sai_attribute_t> attrs;

    attr.id = SAI_LAG_MEMBER_ATTR_LAG_ID;
    attr.value.oid = lag.m_lag_id;
    attrs.push_back(attr);

    attr.id = SAI_LAG_MEMBER_ATTR_PORT_ID;
    attr.value.oid = port.m_port_id;
    attrs.push_back(attr);

    sai_object_id_t lag_member_id;
    sai_status_t status = sai_lag_api->create_lag_member(&lag_member_id, attrs.size(), attrs.data());

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to add member %s to LAG %s lid:%llx pid:%llx\n",
                port.m_alias.c_str(), lag.m_alias.c_str(), lag.m_lag_id, port.m_port_id);
        return false;
    }

    SWSS_LOG_ERROR("Add member %s to LAG %s lid:%llx pid:%llx\n",
            port.m_alias.c_str(), lag.m_alias.c_str(), lag.m_lag_id, port.m_port_id);

    port.m_type = Port::LAG_MEMBER;
    port.m_lag_id = lag.m_lag_id;
    port.m_lag_member_id = lag_member_id;
    m_portsOrch->setPort(port.m_alias, port);
    m_lags[lag.m_alias].insert(port.m_alias);

    return true;
}

bool LagOrch::removeLagMember(Port lag, Port port)
{
    sai_status_t status = sai_lag_api->remove_lag_member(port.m_lag_member_id);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to remove member %s from LAG %s lid:%llx lmid:%llx",
                port.m_alias.c_str(), lag.m_alias.c_str(), lag.m_lag_id, port.m_lag_member_id);
        return false;
    }

    SWSS_LOG_ERROR("Remove member %s from LAG %s lid:%llx lmid:%llx",
            port.m_alias.c_str(), lag.m_alias.c_str(), lag.m_lag_id, port.m_lag_member_id);

    m_lags[lag.m_alias].erase(port.m_alias);
    port.m_type = Port::PHY_PORT;
    m_portsOrch->setPort(port.m_alias, port);

    return true;
}