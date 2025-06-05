#include <cassert>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <exception>

#include "sai.h"
#include "macaddress.h"
#include "ipaddress.h"
#include "orch.h"
#include "request_parser.h"
#include "mclagaaorch.h"
#include "vxlanorch.h"
#include "directory.h"
#include "exec.h"
#include <regex>

extern sai_router_interface_api_t  *sai_router_intfs_api;
extern sai_port_api_t *sai_port_api;
extern PortsOrch      *gPortsOrch;
extern sai_object_id_t gSwitchId;
extern MacAddress gMacAddress;

#define IP_CMD               "/sbin/ip"

static inline std::string shellquote(const std::string& str)
{
    static const std::regex re("([$`\"\\\n])");
    return "\"" + std::regex_replace(str, re, "\\$1") + "\"";
}

MclagAaOrch::MclagAaOrch(DBConnector *appDb, DBConnector *stateDb, const vector<TableConnector> &connectors) :
    Orch(connectors),
    m_appMclagTable(appDb, APP_MCLAG_TABLE_NAME),
    m_stateMclagLocalIntfTable(stateDb, STATE_MCLAG_LOCAL_INTF_TABLE_NAME)
{

}

std::string MclagAaOrch::getMclagSystemMacAddress()
{
    std::string value = "";
    vector<string> keys;
    m_appMclagTable.getKeys(keys);

    for (const auto &key : keys)
    {
        m_appMclagTable.hget(key, "oper_status", value);
        if (value != "up")
           continue;

        m_appMclagTable.hget(key, "system_mac", value);
        if (value != "")
        {
            return value;
        }
    }

    return "";
}

void MclagAaOrch::changeVlanMacAddress(string& vlanName, std::string mac)
{
    stringstream cmd;
    string res;

    // ip link set dev <vlan_name> down
    // ip link set dev <vlan_name> address <new mac address>
    // ip link set dev <vlan_name> up
    cmd << IP_CMD << " link set dev " << shellquote(vlanName) << " down && ";
    cmd << IP_CMD << " link set dev " << shellquote(vlanName)
        << " address " << shellquote(mac) << " && ";
    cmd << IP_CMD << " link set dev " << shellquote(vlanName) << " up";

    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("MclagAaOrch::Command '%s' failed with rc %d", cmd.str().c_str(), ret);
    }
}
bool MclagAaOrch::addVirtualRouterInterface(Port& vlan, std::string& mac)
{
    sai_attribute_t attr;
    vector<sai_attribute_t> vmac_attrs;
    sai_object_id_t rif_id;
    MacAddress macAddr(mac);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
    memcpy(attr.value.mac, macAddr.getMac(), sizeof(sai_mac_t));
    vmac_attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_VLAN;
    vmac_attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_VLAN_ID;
    attr.value.oid = vlan.m_vlan_info.vlan_oid;
    vmac_attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
    attr.value.oid = vlan.m_vr_id;
    vmac_attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_IS_VIRTUAL;
    attr.value.booldata =  true;
    vmac_attrs.push_back(attr);

    sai_status_t status = sai_router_intfs_api->create_router_interface(&rif_id, gSwitchId, (uint32_t)vmac_attrs.size(), vmac_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("MclagAaOrch::Failed to program virtual mac on interface %s, mac = %s, rv:%d",
                       vlan.m_alias.c_str(), mac.c_str(), status);
        return false;
    }

    SWSS_LOG_INFO("MclagAaOrch::Add virtual router interface for vlan %s, mac = %s", vlan.m_alias.c_str(), mac.c_str());

    vlan.m_mclag_rif_id = rif_id;

    return true;
}

bool MclagAaOrch::removeVirtualRouterInterface(Port& vlan)
{
    sai_status_t status = sai_router_intfs_api->remove_router_interface(vlan.m_mclag_rif_id);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("MclagAaOrch::Failed to remove virtual router interface for port %s, rv:%d", vlan.m_alias.c_str(), status);
        return false;
    }

    SWSS_LOG_INFO("MclagAaOrch::Remove virtual router interface for vlan %s", vlan.m_alias.c_str());

    vlan.m_mclag_rif_id = 0;

    return true;
}

bool MclagAaOrch::updateL3VniStatus(uint16_t vlan_id, bool isUp)
{
    Port vlan;
    string vlan_alias;

    vlan_alias = VLAN_PREFIX + to_string(vlan_id);

    if (!gPortsOrch->getPort(vlan_alias, vlan))
    {
        SWSS_LOG_INFO("Failed to locate VLAN %d", vlan_id);
        return false;
    }

    if (isUp)
    {
        std::string system_mac = getMclagSystemMacAddress();
        if (system_mac != "" && vlan.m_mclag_rif_id == 0)
        {
            addVirtualRouterInterface(vlan, system_mac);
            changeVlanMacAddress(vlan_alias, system_mac);
        }
    }
    else
    {
        if (vlan.m_mclag_rif_id != 0)
        {
            removeVirtualRouterInterface(vlan);
            changeVlanMacAddress(vlan_alias, gMacAddress.to_string());
        }
    }

    gPortsOrch->setPort(vlan_alias, vlan);

    return true;
}

bool MclagAaOrch::setMclagPeerlinkPort(sai_object_id_t m_port_id, bool is_peerlink)
{
    sai_attribute_t attr;

    attr.id = SAI_PORT_ATTR_MCLAG_PEER_LINK;
    attr.value.booldata = is_peerlink;
    sai_status_t status = sai_port_api->set_port_attribute(m_port_id, &attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("MclagAaOrch::Failed to set peerlink %d to port pid:%" PRIx64 ", rv:%d",
                attr.value.booldata, m_port_id, status);
        return false;
    }

    SWSS_LOG_INFO("MclagAaOrch:: set peerlink %d to port pid:%" PRIx64, attr.value.booldata, m_port_id);
    return true;
}

bool MclagAaOrch::setMclagPeerlink(Port &port, bool is_peerlink)
{
    vector<Port> portv;
    SWSS_LOG_ENTER();

    SWSS_LOG_INFO("MclagAaOrch:: set peerlink port:%" PRIx64 ", name: %s", port.m_port_id, port.m_alias.c_str());

    if (port.m_type == Port::PHY)
    {
        if (!setMclagPeerlinkPort(port.m_port_id, is_peerlink))
        {
            return false;
        }
        port.is_peerlink = is_peerlink;
        gPortsOrch->setPort(port.m_alias, port);
    }
    else if (port.m_type == Port::LAG)
    {
        gPortsOrch->getLagMember(port, portv);
        for (const auto p: portv)
        {
            if (!setMclagPeerlinkPort(p.m_port_id, is_peerlink))
            {
                return false;
            }
        }
        port.is_peerlink = is_peerlink;
        gPortsOrch->setPort(port.m_alias, port);
    }
    else
    {
        SWSS_LOG_ERROR("MclagAaOrch::Not support port:%" PRIx64 ", name: %s", port.m_port_id, port.m_alias.c_str());
        return false;
    }

    return true;
}

void MclagAaOrch::doPeerlinkTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    Port p;
    string platform = getenv("platform") ? getenv("platform") : "";
    if (platform != BRCM_PLATFORM_SUBSTRING)
    {
        SWSS_LOG_DEBUG("This platform %s does not support Mclag.", platform.c_str());
        consumer.m_toSync.clear();
        return;
    }

    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        auto &t = it->second;

        string key = kfvKey(t);
        string op = kfvOp(t);
        string port_name = "", system_mac = "", oper_status = "";

        SWSS_LOG_INFO("MclagAaOrch::key %s op %s", key.c_str(), op.c_str());

        if (op == SET_COMMAND)
        {
            for (auto i : kfvFieldsValues(t))
            {
                if (fvField(i) == "peer_link")
                    port_name = fvValue(i);
                if (fvField(i) == "oper_status")
                    oper_status = fvValue(i);
            }

            /* create overlay virtual router interface for mclag system mac */
            for (auto &port_it: gPortsOrch->getAllPorts())
            {
                if (port_it.second.m_type == Port::VLAN && port_it.second.m_l3_vni == true)
                {
                    system_mac = getMclagSystemMacAddress();
                    if (system_mac != "" && port_it.second.m_mclag_rif_id == 0)
                    {
                        addVirtualRouterInterface(port_it.second, system_mac);
                        changeVlanMacAddress(port_it.second.m_alias, system_mac);
                    }

                    if (system_mac == "" && port_it.second.m_mclag_rif_id != 0)
                    {
                        removeVirtualRouterInterface(port_it.second);
                        changeVlanMacAddress(port_it.second.m_alias, gMacAddress.to_string());
                    }
                }
            }

            if (port_name != "")
                peerlink_intf_name[key] = port_name;

            if (oper_status != "")
            {
                if (peerlink_intf_name.find(key) == peerlink_intf_name.end())
                {
                    it++;
                    continue;
                }

                port_name = peerlink_intf_name[key];

                if (gPortsOrch->getPort(port_name, p))
                {
                    if (!setMclagPeerlink(p, oper_status == "up" ? true : false))
                    {
                        it++;
                        continue;
                    }
                }
            }

            it = consumer.m_toSync.erase(it);
        }
        else if (op == DEL_COMMAND)
        {
            for (auto i : kfvFieldsValues(t))
            {
                if (fvField(i) == "peer_link")
                    port_name = fvValue(i);
            }

            /* remove overlay virtual router interface of mclag system mac */
            for (auto &port_it : gPortsOrch->getAllPorts())
            {
                if (port_it.second.m_type == Port::VLAN && port_it.second.m_l3_vni == true)
                {
                    system_mac = getMclagSystemMacAddress();
                    if (system_mac == "" && port_it.second.m_mclag_rif_id != 0)
                    {
                        removeVirtualRouterInterface(port_it.second);
                        changeVlanMacAddress(port_it.second.m_alias, gMacAddress.to_string());
                    }
                }
            }
            if (peerlink_intf_name.find(key) == peerlink_intf_name.end())
            {
                it = consumer.m_toSync.erase(it);
                continue;
            }

            if (port_name == "" && peerlink_intf_name[key]!= "")
            {
                port_name = peerlink_intf_name[key];
            }
            peerlink_intf_name.erase(key);

            if (port_name == "")
            {
                it = consumer.m_toSync.erase(it);
                continue;
            }

            if (!gPortsOrch->getPort(port_name, p))
            {
                SWSS_LOG_ERROR("MclagAaOrch::Failed to get %s info", port_name.c_str());
                it = consumer.m_toSync.erase(it);
                continue;
            }

            if (setMclagPeerlink(p,false))
                it = consumer.m_toSync.erase(it);
            else
                it++;
        }
        else
        {
            SWSS_LOG_ERROR("MclagAaOrch::Unknown operation type %s", op.c_str());
            it = consumer.m_toSync.erase(it);
        }
    }
}

void MclagAaOrch::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    if (!gPortsOrch->allPortsReady())
    {
        return;
    }

    string table_name = consumer.getTableName();

    if (table_name == APP_MCLAG_TABLE_NAME)
    {
        SWSS_LOG_INFO("MclagAaOrch::doTask APP_MCLAG_TABLE_NAME");
        doPeerlinkTask(consumer);
    }
    else if (table_name == STATE_MCLAG_LOCAL_INTF_TABLE_NAME)
    {
        SWSS_LOG_INFO("MclagAaOrch::doTask STATE_MCLAG_LOCAL_INTF_TABLE_NAME");
        //doPortIsolateTask(consumer);
        consumer.m_toSync.clear();
    }
    else
    {
        SWSS_LOG_ERROR("MclagAaOrch::Unknown table %s", table_name.c_str());
    }
}
