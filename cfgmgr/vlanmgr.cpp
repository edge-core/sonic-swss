#include <string.h>
#include "logger.h"
#include "producerstatetable.h"
#include "macaddress.h"
#include "vlanmgr.h"
#include "exec.h"
#include "tokenize.h"
#include "shellcmd.h"
#include "warm_restart.h"
#include <swss/redisutility.h>
#include "subintf.h"

using namespace std;
using namespace swss;

#define DOT1Q_BRIDGE_NAME   "Bridge"
#define DFLT_BR_AGE_TIME    "600"
#define VLAN_PREFIX         "Vlan"
#define LAG_PREFIX          "PortChannel"
#define DEFAULT_VLAN_ID     "1"
#define DEFAULT_MTU_STR     "9100"
#define VLAN_HLEN            4
#define NFT_ARP_CHAIN       "ARP_LIST"
#define NFT_ND_CHAIN        "ND_LIST"
#define NFT_VLAN_ARP_CHAIN  "VLAN_ARP_LIST"

extern MacAddress gMacAddress;

VlanMgr::VlanMgr(DBConnector *cfgDb, DBConnector *appDb, DBConnector *stateDb, const vector<TableConnector> &tables) :
        Orch(tables),
        m_cfgVlanTable(cfgDb, CFG_VLAN_TABLE_NAME),
        m_cfgVlanMemberTable(cfgDb, CFG_VLAN_MEMBER_TABLE_NAME),
        m_cfgNeighSuppressVlanTable(cfgDb, CFG_NEIGH_SUPPRESS_VLAN_TABLE_NAME),
        m_statePortTable(stateDb, STATE_PORT_TABLE_NAME),
        m_stateLagTable(stateDb, STATE_LAG_TABLE_NAME),
        m_stateVlanTable(stateDb, STATE_VLAN_TABLE_NAME),
        m_stateVlanMemberTable(stateDb, STATE_VLAN_MEMBER_TABLE_NAME),
        m_stateNeighSuppressVlanTable(stateDb, STATE_NEIGH_SUPPRESS_VLAN_TABLE_NAME),
        m_appVlanTableProducer(appDb, APP_VLAN_TABLE_NAME),
        m_appVlanMemberTableProducer(appDb, APP_VLAN_MEMBER_TABLE_NAME),
        m_cfgSubInterfaceTable(cfgDb, CFG_VLAN_SUB_INTF_TABLE_NAME),
        m_appNeighSuppressVlanTableProducer(appDb, APP_NEIGH_SUPPRESS_VLAN_TABLE_NAME),
        replayDone(false)
{
    SWSS_LOG_ENTER();

    std::string nftables_cmd, res;
    nftables_cmd = std::string("") + "nft flush chain bridge filter " + NFT_ARP_CHAIN;
    swss::exec(nftables_cmd.c_str(), res);
    nftables_cmd = std::string("") + "nft flush chain bridge filter " + NFT_ND_CHAIN;
    swss::exec(nftables_cmd.c_str(), res);
    nftables_cmd = std::string("") + "nft flush chain bridge filter " + NFT_VLAN_ARP_CHAIN;
    swss::exec(nftables_cmd.c_str(), res);
    int ret;

    if (WarmStart::isWarmStart())
    {
        vector<string> vlanKeys, vlanMemberKeys;

        /* cache all vlan and vlan member config */
        m_cfgVlanTable.getKeys(vlanKeys);
        m_cfgVlanMemberTable.getKeys(vlanMemberKeys);
        for (auto k : vlanKeys)
        {
            m_vlanReplay.insert(k);
        }
        for (auto k : vlanMemberKeys)
        {
            m_vlanMemberReplay.insert(k);
        }
        if (m_vlanReplay.empty())
        {
            replayDone = true;
            WarmStart::setWarmStartState("vlanmgrd", WarmStart::REPLAYED);
            SWSS_LOG_NOTICE("vlanmgr warmstart state set to REPLAYED");
            WarmStart::setWarmStartState("vlanmgrd", WarmStart::RECONCILED);
            SWSS_LOG_NOTICE("vlanmgr warmstart state set to RECONCILED");
        }
        const std::string cmds = std::string("")
          + IP_CMD + " link show " + DOT1Q_BRIDGE_NAME + " 2>/dev/null";

        std::string res;
        ret = swss::exec(cmds, res);
        if (ret == 0)
        {
            // Don't reset vlan aware bridge upon swss docker warm restart.
            SWSS_LOG_INFO("vlanmgrd warm start, skipping bridge create");
            return;
        }
    }
    // Initialize Linux dot1q bridge and enable vlan filtering
    // The command should be generated as:
    // /bin/bash -c "/sbin/ip link del Bridge 2>/dev/null ;
    //               /sbin/ip link add Bridge up type bridge &&
    //               /sbin/ip link set Bridge mtu {{ mtu_size }} &&
    //               /sbin/ip link set Bridge address {{gMacAddress}} &&
    //               /sbin/ip link set Bridge addrgenmode none &&
    //               /sbin/ip address flush Bridge &&
    //               /sbin/bridge vlan del vid 1 dev Bridge self;
    //               /sbin/ip link del dummy 2>/dev/null;
    //               /sbin/ip link add dummy type dummy &&
    //               /sbin/ip link set dummy master Bridge"

    const std::string cmds = std::string("")
      + BASH_CMD + " -c \""
      + IP_CMD + " link del " + DOT1Q_BRIDGE_NAME + " 2>/dev/null; "
      + IP_CMD + " link add " + DOT1Q_BRIDGE_NAME + " up type bridge && "
      + IP_CMD + " link set " + DOT1Q_BRIDGE_NAME + " mtu " + DEFAULT_MTU_STR + " && "
      + IP_CMD + " link set " + DOT1Q_BRIDGE_NAME + " address " + gMacAddress.to_string() + " && "
      + IP_CMD + " link set " + DOT1Q_BRIDGE_NAME + " addrgenmode none && "
      + IP_CMD + " address flush " + DOT1Q_BRIDGE_NAME + " && "
      + BRIDGE_CMD + " vlan del vid " + DEFAULT_VLAN_ID + " dev " + DOT1Q_BRIDGE_NAME + " self; "
      + IP_CMD + " link del dev dummy 2>/dev/null; "
      + IP_CMD + " link add dummy type dummy && "
      + IP_CMD + " link set dummy master " + DOT1Q_BRIDGE_NAME + "\"";

    ret = swss::exec(cmds, res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmds.c_str(), ret);
    }

    // The generated command is:
    // /bin/echo 1 > /sys/class/net/Bridge/bridge/vlan_filtering
    const std::string echo_cmd = std::string("")
      + ECHO_CMD + " 1 > /sys/class/net/" + DOT1Q_BRIDGE_NAME + "/bridge/vlan_filtering";

    ret = swss::exec(echo_cmd, res);
    /* echo will fail in virtual switch since /sys directory is read-only.
     * need to use ip command to setup the vlan_filtering which is not available in debian 8.
     * Once we move sonic to debian 9, we can use IP command by default
     * ip command available in Debian 9 to create a bridge with a vlan filtering:
     * /sbin/ip link add Bridge up type bridge vlan_filtering 1 */
    if (ret != 0)
    {
        const std::string echo_cmd_backup = std::string("")
          + IP_CMD + " link set " + DOT1Q_BRIDGE_NAME + " type bridge vlan_filtering 1";

        int ret_2 = swss::exec(echo_cmd_backup, res);
        if (ret_2)
        {
            SWSS_LOG_ERROR("Command '%s' failed with rc %d", echo_cmd_backup.c_str(), ret_2);
        }
    }

    // not learn from link-local frames
    // /bin/echo 1 > /sys/class/net/Bridge/bridge/no_linklocal_learn
    const std::string no_ll_learn_cmd = std::string("")
      + ECHO_CMD + " 1 > /sys/class/net/" + DOT1Q_BRIDGE_NAME + "/bridge/no_linklocal_learn";

    ret = swss::exec(no_ll_learn_cmd, res);
    if (ret) {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", no_ll_learn_cmd.c_str(), ret);
    }

    // Initialize Linux dot1q bridge ageing time based on SWITCH_TABLE from APPL_DB
    // The command should be generated as:
    // /bin/bash -c "/sbin/brctl setageing Bridge 600"
    const std::string brctl_cmd = std::string("")
        + BRCTL_CMD + " setageing " + DOT1Q_BRIDGE_NAME + " " + DFLT_BR_AGE_TIME;
    ret = swss::exec(brctl_cmd, res);
    if (ret) {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", brctl_cmd.c_str(), ret);
    }
}

bool VlanMgr::addHostVlan(int vlan_id)
{
    SWSS_LOG_ENTER();

    // The command should be generated as:
    // /bin/bash -c "/sbin/bridge vlan add vid {{vlan_id}} dev Bridge self &&
    //               /sbin/ip link add link Bridge up name Vlan{{vlan_id}} address {{gMacAddress}} type vlan id {{vlan_id}}"
    const std::string cmds = std::string("")
      + BASH_CMD + " -c \""
      + BRIDGE_CMD + " vlan add vid " + std::to_string(vlan_id) + " dev " + DOT1Q_BRIDGE_NAME + " self && "
      + IP_CMD + " link add link " + DOT1Q_BRIDGE_NAME
               + " up"
               + " name " + VLAN_PREFIX + std::to_string(vlan_id)
               + " address " + gMacAddress.to_string()
               + " type vlan id " + std::to_string(vlan_id) + "\"";

    std::string res;
    int ret = swss::exec(cmds, res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmds.c_str(), ret);
    }

    res.clear();
    const std::string echo_cmd = std::string("")
      + ECHO_CMD + " 0 > /proc/sys/net/ipv4/conf/" + VLAN_PREFIX + std::to_string(vlan_id) + "/arp_evict_nocarrier";
    swss::exec(echo_cmd, res);

    return true;
}

bool VlanMgr::removeHostVlan(int vlan_id)
{
    SWSS_LOG_ENTER();

    // The command should be generated as:
    // /bin/bash -c "/sbin/ip link del Vlan{{vlan_id}} &&
    //               /sbin/bridge vlan del vid {{vlan_id}} dev Bridge self"
    const std::string cmds = std::string("")
      + BASH_CMD + " -c \""
      + IP_CMD + " link del " + VLAN_PREFIX + std::to_string(vlan_id) + " && "
      + BRIDGE_CMD + " vlan del vid " + std::to_string(vlan_id) + " dev " + DOT1Q_BRIDGE_NAME + " self\"";

    std::string res;
    int ret = swss::exec(cmds, res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmds.c_str(), ret);
    }

    return true;
}

bool VlanMgr::setHostVlanAdminState(int vlan_id, const string &admin_status)
{
    SWSS_LOG_ENTER();

    // The command should be generated as:
    // /sbin/ip link set Vlan{{vlan_id}} {{admin_status}}
    ostringstream cmds;
    cmds << IP_CMD " link set " VLAN_PREFIX + std::to_string(vlan_id) + " " << shellquote(admin_status);

    std::string res;
    int ret = swss::exec(cmds.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmds.str().c_str(), ret);
    }
    return true;
}

bool VlanMgr::setHostVlanMtu(int vlan_id, uint32_t mtu)
{
    SWSS_LOG_ENTER();

    // The command should be generated as:
    // /sbin/ip link set Vlan{{vlan_id}} mtu {{mtu}}
    const std::string cmds = std::string("")
      + IP_CMD + " link set " + VLAN_PREFIX + std::to_string(vlan_id) + " mtu " + std::to_string(mtu);

    std::string res;
    int ret = swss::exec(cmds, res);
    if (ret == 0)
    {
        return true;
    }

    /* VLAN mtu should not be larger than member mtu */
    return false;
}

bool VlanMgr::setHostVlanMac(int vlan_id, const string &mac)
{
    SWSS_LOG_ENTER();

    // The command should be generated as:
    // /sbin/ip link set Vlan{{vlan_id}} address {{mac}}
    ostringstream cmds;
    cmds << IP_CMD " link set " VLAN_PREFIX + std::to_string(vlan_id) + " address " << shellquote(mac) << " && "
            IP_CMD " link set " DOT1Q_BRIDGE_NAME " address " << shellquote(mac);

    std::string res;
    int ret = swss::exec(cmds.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmds.str().c_str(), ret);
    }

    return true;
}

bool VlanMgr::addHostVlanMember(int vlan_id, const string &port_alias, const string& tagging_mode)
{
    SWSS_LOG_ENTER();
    string key_def_vlan = VLAN_PREFIX DEFAULT_VLAN_ID CONFIGDB_KEY_SEPARATOR + port_alias;

    std::string tagging_cmd;
    if (tagging_mode == "untagged" || tagging_mode == "priority_tagged")
    {
        tagging_cmd = "pvid untagged";
    }

    // The command should be generated as:
    // /bin/bash -c "/sbin/ip link set {{port_alias}} master Bridge &&
    //               /sbin/bridge vlan del vid 1 dev {{ port_alias }} &&
    //               /sbin/bridge vlan add vid {{vlan_id}} dev {{port_alias}} {{tagging_mode}}"
    ostringstream cmds, inner;
    if (!isVlanMemberStateOk(key_def_vlan))
    {
        inner << IP_CMD " link set " << shellquote(port_alias) << " master " DOT1Q_BRIDGE_NAME " && "
          BRIDGE_CMD " vlan del vid " DEFAULT_VLAN_ID " dev " << shellquote(port_alias) << " && "
          BRIDGE_CMD " vlan add vid " + std::to_string(vlan_id) + " dev " << shellquote(port_alias) << " " + tagging_cmd;
    }
    else
    {
        inner << IP_CMD " link set " << shellquote(port_alias) << " master " DOT1Q_BRIDGE_NAME " && "
          BRIDGE_CMD " vlan add vid " + std::to_string(vlan_id) + " dev " << shellquote(port_alias) << " " + tagging_cmd;
    }
    cmds << BASH_CMD " -c " << shellquote(inner.str());

    std::string res;
    int ret = swss::exec(cmds.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmds.str().c_str(), ret);
    }

    vector<FieldValueTuple> values;
    if (isVlanNeighborSuppressed(vlan_id)
        && m_stateNeighSuppressVlanTable.get(string("Vlan") + to_string(vlan_id), values))
    {
        updateVlanMemberNftRule(vlan_id, port_alias, true);
    }

    return true;
}

bool VlanMgr::removeHostVlanMember(int vlan_id, const string &port_alias)
{
    SWSS_LOG_ENTER();

    // The command should be generated as:
    // /bin/bash -c '/sbin/bridge vlan del vid {{vlan_id}} dev {{port_alias}} &&
    //               ( vlanShow=$(/sbin/bridge vlan show dev {{port_alias}});
    //               ret=$?;
    //               if [ $ret -eq 0 ]; then
    //               if (! echo "$vlanShow" | grep -q {{port_alias}})
    //                 || (echo "$vlanShow" | grep -q None$)
    //                 || (echo "$vlanShow" | grep -q {{port_alias}}$); then
    //               /sbin/ip link set {{port_alias}} nomaster;
    //               fi;
    //               else exit $ret; fi )'

    // When port is not member of any VLAN, it shall be detached from Dot1Q bridge!
    ostringstream cmds, inner;
    inner << BRIDGE_CMD " vlan del vid " + std::to_string(vlan_id) + " dev " << shellquote(port_alias) << " && ( "
      "vlanShow=$(" BRIDGE_CMD " vlan show dev " << shellquote(port_alias) << "); "
      "ret=$?; "
      "if [ $ret -eq 0 ]; then "
      "if (! echo \"$vlanShow\" | " GREP_CMD " -q " << shellquote(port_alias) << ") "
      " || (echo \"$vlanShow\" | " GREP_CMD " -q None$) "
      " || (echo \"$vlanShow\" | " GREP_CMD " -q " << shellquote(port_alias) << "$); then "
      IP_CMD " link set " << shellquote(port_alias) << " nomaster; "
      "fi; "
      "else exit $ret; fi )";
    cmds << BASH_CMD " -c " << shellquote(inner.str());

    std::string res;
    int ret = swss::exec(cmds.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmds.str().c_str(), ret);
    }
    updateVlanMemberNftRule(vlan_id, port_alias, false);
    return true;
}

bool VlanMgr::isVlanMacOk()
{
    return !!gMacAddress;
}
bool VlanMgr::isSubportConfigVlan(const int vlan_id)
{
    std::vector<std::string> keys;
    m_cfgSubInterfaceTable.getKeys(keys);
    for (const auto& tmp_key : keys)
    {
        if (tmp_key.find(VLAN_SUB_INTERFACE_SEPARATOR) == string::npos)
        {
            continue;
        }
        subIntf subIf(tmp_key);
        if (vlan_id && vlan_id == subIf.subIntfIdx())
        {
            return true;
        }
    }
    return false;
}

bool VlanMgr::isVlanNeighborSuppressed(int vlan_id)
{
    string key = VLAN_PREFIX + to_string(vlan_id);
    string neighbor_suppress_str;

    m_cfgNeighSuppressVlanTable.hget(key.c_str(), "suppress", neighbor_suppress_str);
    return (neighbor_suppress_str == "on") ? true : false;
}

bool VlanMgr::setNftRule(const std::string &chain_name, const std::string port_alias, bool is_add, int vlan_id)
{
    std::string nftables_cmd, res;
    std::string key = chain_name;
    key = key + "_" + to_string(vlan_id);

    if (is_add)
    {
        if (m_nftNdSpRuleHandles.find(key) != m_nftNdSpRuleHandles.end())
            if (m_nftNdSpRuleHandles[key].find(port_alias) != m_nftNdSpRuleHandles[key].end())
                return true;
        if (port_alias.find("vtep") != std::string::npos)
            nftables_cmd = "nft --echo --handle add rule bridge filter " + chain_name + " oifname " + port_alias +
                           " counter packets 0 bytes 0 accept | grep handle | awk '{print $NF}'";
        else if (m_nftVlanMbrSetMap[vlan_id] != "")
            nftables_cmd = "nft --echo --handle add rule bridge filter " + chain_name + " iifname " + port_alias +
                           " oifname == @" + m_nftVlanMbrSetMap[vlan_id] + " counter packets 0 bytes 0 accept | grep handle | awk '{print $NF}'";
        else
            return false;
    }
    else
    {
        auto it = m_nftNdSpRuleHandles.find(key);

        if (it != m_nftNdSpRuleHandles.end())
            nftables_cmd = "nft --echo --handle delete rule bridge filter "  + chain_name + " handle " + (it->second)[port_alias];
        else
            return false;
    }

    swss::exec(nftables_cmd.c_str(), res);

    if (is_add)
    {
        SWSS_LOG_INFO("Success to add nftables rule, key = [%s], handle = [%s]", key.c_str(), res.c_str());
        m_nftNdSpRuleHandles[key].insert(std::make_pair(port_alias, res));
    }
    else
        m_nftNdSpRuleHandles[key].erase(port_alias);

    return true;
}

void VlanMgr::updateNftVlanMbrSet(int vlan_id, bool is_set)
{
    string res, nft_set_cmd, set_name = "vlan" + to_string(vlan_id) + "_mbr";;

    if (is_set)
    {
        nft_set_cmd = "nft add set bridge filter " + set_name + " { type ifname\\; }";
        swss::exec(nft_set_cmd.c_str(), res);
        m_nftVlanMbrSetMap[vlan_id] = set_name;
    }
    else
    {
        nft_set_cmd = "nft delete set bridge filter " + m_nftVlanMbrSetMap[vlan_id];
        swss::exec(nft_set_cmd.c_str(), res);
        m_nftVlanMbrSetMap.erase(vlan_id);
    }
}

void VlanMgr::updateNftVlanMbrSetElement(int vlan_id, const std::string port_alias, std::string op)
{
    string res, element = "'{ " + port_alias + " }'";
    string nft_set_element_cmd = "nft " + op +" element bridge filter " + m_nftVlanMbrSetMap[vlan_id] + element;

    if (op == "add")
    {
        if (m_nftVlanMbrSetElement[vlan_id].find(port_alias) == m_nftVlanMbrSetElement[vlan_id].end())
        {
            m_nftVlanMbrSetElement[vlan_id].insert(port_alias);
            swss::exec(nft_set_element_cmd.c_str(), res);
        }
    }
    else
    {
        m_nftVlanMbrSetElement[vlan_id].erase(port_alias);
        swss::exec(nft_set_element_cmd.c_str(), res);
    }
}

void VlanMgr::updateVlanMemberNftRule(int vlan_id, const std::string port_alias, bool is_add)
{
    SWSS_LOG_INFO("Update nftables rule for port %s, vlan %d, is_add %d", port_alias.c_str(), vlan_id, is_add);

    if (is_add)
    {
        updateNftVlanMbrSet(vlan_id, true);

        // add ebtable rules
        if (setNftRule(NFT_ARP_CHAIN, port_alias, true, vlan_id)
            && setNftRule(NFT_VLAN_ARP_CHAIN, port_alias, true, vlan_id)
            && setNftRule(NFT_ND_CHAIN, port_alias, true, vlan_id))
        {
            SWSS_LOG_INFO("ADD nftables rule for port %s, vlan %d, is_add %d", port_alias.c_str(), vlan_id, is_add);

            updateNftVlanMbrSetElement(vlan_id, port_alias, "add");
        }
        else
        {
            SWSS_LOG_INFO("failed to add nftable rules");
        }
    }
    else
    {
        if (m_nftVlanMbrSetElement.find(vlan_id) != m_nftVlanMbrSetElement.end())
        {
            // only remove ebtable rules when the port is not member of any VLAN
            if (m_nftVlanMbrSetElement[vlan_id].size())
            {
                // remove nftables rules
                if (setNftRule(NFT_ARP_CHAIN, port_alias, false, vlan_id)
                    && setNftRule(NFT_VLAN_ARP_CHAIN, port_alias, false, vlan_id)
                    && setNftRule(NFT_ND_CHAIN, port_alias, false, vlan_id))
                {
                    updateNftVlanMbrSetElement(vlan_id, port_alias, "delete");
                }
                else
                {
                    SWSS_LOG_INFO("failed to delete nftable rules");
                }
            }

            if (m_nftVlanMbrSetElement[vlan_id].size() == 0)
            {
                m_neighborSuppressMap.erase(port_alias);
                updateNftVlanMbrSet(vlan_id, false);
            }
        }
    }
}

void VlanMgr::updateVlanMemberNftRule(int vlan_id, bool is_add)
{
    SWSS_LOG_INFO("Update nftables rule for all members of vlan %d, is_add %d", vlan_id, is_add);

    vector<string> vlanMemberKeys;
    string vlan_alias = VLAN_PREFIX + to_string(vlan_id);

    m_cfgVlanMemberTable.getKeys(vlanMemberKeys);
    for (auto key: vlanMemberKeys)
    {
        size_t delimeter = key.find(CONFIGDB_KEY_SEPARATOR);
        if (delimeter != string::npos)
        {
            string vlan_str = key.substr(0, delimeter);
            if (!vlan_str.compare(vlan_alias))
            {
                string port_alias = key.substr(delimeter+1);
                int vlan_id;
                try
                {
                    vlan_id = stoi(key.substr(4));
                }
                catch (...)
                {
                    SWSS_LOG_ERROR("Invalid key format. Not a number after 'Vlan' prefix: %s", key.c_str());
                    continue;
                }

                if (is_add)
                {
                    if (m_neighborSuppressMap.find(port_alias) == m_neighborSuppressMap.end())
                    {
                        m_neighborSuppressMap[port_alias] = std::set<int>();
                    }

                    // add ebtable rules
                    if (setNftRule(NFT_ARP_CHAIN, port_alias, true)
                        && setNftRule(NFT_VLAN_ARP_CHAIN, port_alias, true)
                        && setNftRule(NFT_ND_CHAIN, port_alias, true))
                    {
                        SWSS_LOG_NOTICE("ADD nftables rule for port %s, vlan %d, is_add %d", port_alias.c_str(), vlan_id, is_add);
                        m_neighborSuppressMap[port_alias].insert(vlan_id);
                    }
                    else
                    {
                        SWSS_LOG_INFO("failed to add ebtable rules");
                    }
                }
                else
                {
                    auto it = m_neighborSuppressMap.find(port_alias);
                    if (it != m_neighborSuppressMap.end())
                    {
                        auto &vlanSet = it->second;

                        // only remove ebtable rules when the port is not member of any VLAN
                        if (vlanSet.size() == 1 && vlanSet.count(vlan_id))
                        {
                            // remove nftables rules
                            if (setNftRule(NFT_ARP_CHAIN, port_alias, false)
                                && setNftRule(NFT_VLAN_ARP_CHAIN, port_alias, false)
                                && setNftRule(NFT_ND_CHAIN, port_alias, false))
                            {
                                SWSS_LOG_NOTICE("ERASE nftables rule for port %s, vlan %d, is_add %d", port_alias.c_str(), vlan_id, is_add);
                                vlanSet.erase(vlan_id);
                                m_neighborSuppressMap.erase(port_alias);
                            }
                            else
                            {
                                SWSS_LOG_INFO("failed to add ebtable rules");
                            }
                        }
                        else if (vlanSet.size() == 0)
                        {
                            SWSS_LOG_ERROR("Vlan set is empty for port %s", port_alias.c_str());
                            // remove nftables rules
                            if (setNftRule(NFT_ARP_CHAIN, port_alias, false)
                                && setNftRule(NFT_VLAN_ARP_CHAIN, port_alias, false)
                                && setNftRule(NFT_ND_CHAIN, port_alias, false))
                            {
                                SWSS_LOG_NOTICE("ERASE nftables rule for port %s, vlan %d, is_add %d", port_alias.c_str(), vlan_id, is_add);
                                m_neighborSuppressMap.erase(port_alias);
                            }
                        }
                        else
                        {
                            vlanSet.erase(vlan_id);
                        }
                    }
                }
            }
        }
    }
}

void VlanMgr::doVlanTask(Consumer &consumer)
{
    if (!isVlanMacOk())
    {
        SWSS_LOG_DEBUG("VLAN mac not ready, delaying VLAN task");
        return;
    }
    auto it = consumer.m_toSync.begin();

    while (it != consumer.m_toSync.end())
    {
        auto &t = it->second;

        string key = kfvKey(t);

        /* Ensure the key starts with "Vlan" otherwise ignore */
        if (strncmp(key.c_str(), VLAN_PREFIX, 4))
        {
            SWSS_LOG_ERROR("Invalid key format. No 'Vlan' prefix: %s", key.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        int vlan_id;
        try
        {
            vlan_id = stoi(key.substr(4));
        }
        catch (...)
        {
            SWSS_LOG_ERROR("Invalid key format. Not a number after 'Vlan' prefix: %s", key.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        string vlan_alias, port_alias;
        string op = kfvOp(t);

        if (op == SET_COMMAND)
        {
            string admin_status;
            string mtu = DEFAULT_MTU_STR;
            string mac = gMacAddress.to_string();
            string hostif_name = "";
            vector<FieldValueTuple> fvVector;
            string members;

            string platform = getenv("platform") ? getenv("platform") : "";
            if (platform == BRCM_PLATFORM_SUBSTRING && isSubportConfigVlan(vlan_id))
            {
                it = consumer.m_toSync.erase(it);
                SWSS_LOG_ERROR("%s invaild config: subport config the vlan already", key.c_str());
                continue;
            }
            /*
             * If state is already set for this vlan, but it doesn't exist in m_vlans set,
             * just add it to m_vlans set and remove the request to skip disrupting Linux vlan.
             * Will hit this scenario for docker warm restart.
             *
             * Otherwise, it is new VLAN create or VLAN attribute update like admin_status/mtu change,
             * proceed with regular processing.
             */
            if (isVlanStateOk(key) && m_vlans.find(key) == m_vlans.end())
            {
                SWSS_LOG_DEBUG("%s already created", kfvKey(t).c_str());
                m_vlans.insert(key);
                m_vlanReplay.erase(kfvKey(t));
                it = consumer.m_toSync.erase(it);
                continue;
            }

            /* Add host VLAN when it has not been created. */
            if (m_vlans.find(key) == m_vlans.end())
            {
                addHostVlan(vlan_id);
            }
            m_vlanReplay.erase(kfvKey(t));

            /* set up host env .... */
            for (auto i : kfvFieldsValues(t))
            {
                /* Set vlan admin status */
                if (fvField(i) == "admin_status")
                {
                    admin_status = fvValue(i);
                    setHostVlanAdminState(vlan_id, admin_status);
                    fvVector.push_back(i);
                }
                /* Set vlan mtu */
                else if (fvField(i) == "mtu")
                {
                    mtu = fvValue(i);
                    /*
                     * TODO: support host VLAN mtu setting.
                     * Host VLAN mtu should be set only after member configured
                     * and VLAN state is not UNKNOWN.
                     */
                    SWSS_LOG_DEBUG("%s mtu %s: Host VLAN mtu setting to be supported.", key.c_str(), mtu.c_str());
                }
                else if (fvField(i) == "members@") {
                    members = fvValue(i);
                }
                else if (fvField(i) == "mac")
                {
                    mac = fvValue(i);
                    setHostVlanMac(vlan_id, mac);
                }
                else if (fvField(i) == "host_ifname")
                {
                    hostif_name = fvValue(i);
                }
            }
            /* fvVector should not be empty */
            if (fvVector.empty())
            {
                FieldValueTuple a("admin_status",  "up");
                fvVector.push_back(a);
            }

            FieldValueTuple m("mtu", mtu);
            fvVector.push_back(m);

            FieldValueTuple mc("mac", mac);
            fvVector.push_back(mc);

            FieldValueTuple hostif_name_fvt("host_ifname", hostif_name);
            fvVector.push_back(hostif_name_fvt);

            m_appVlanTableProducer.set(key, fvVector);
            m_vlans.insert(key);

            fvVector.clear();
            FieldValueTuple s("state", "ok");
            fvVector.push_back(s);
            m_stateVlanTable.set(key, fvVector);

            it = consumer.m_toSync.erase(it);

            /*
             * Members configured together with VLAN in untagged mode.
             * This is to be compatible with access VLAN configuration from minigraph.
             */
            if (!members.empty())
            {
                processUntaggedVlanMembers(key, members);
            }
        }
        else if (op == DEL_COMMAND)
        {
            if (m_vlans.find(key) != m_vlans.end())
            {
                removeHostVlan(vlan_id);
                m_vlans.erase(key);
                m_appVlanTableProducer.del(key);
                m_stateVlanTable.del(key);
            }
            else
            {
                SWSS_LOG_ERROR("%s doesn't exist", key.c_str());
            }
            SWSS_LOG_DEBUG("%s", (consumer.dumpTuple(t)).c_str());
            it = consumer.m_toSync.erase(it);
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation type %s", op.c_str());
            SWSS_LOG_DEBUG("%s", (consumer.dumpTuple(t)).c_str());
            it = consumer.m_toSync.erase(it);
        }
    }
    if (!replayDone && m_vlanReplay.empty() &&
        m_vlanMemberReplay.empty() &&
        WarmStart::isWarmStart())
    {
        replayDone = true;
        WarmStart::setWarmStartState("vlanmgrd", WarmStart::REPLAYED);
        SWSS_LOG_NOTICE("vlanmgr warmstart state set to REPLAYED");
        WarmStart::setWarmStartState("vlanmgrd", WarmStart::RECONCILED);
        SWSS_LOG_NOTICE("vlanmgr warmstart state set to RECONCILED");
    }
}

bool VlanMgr::isMemberStateOk(const string &alias)
{
    vector<FieldValueTuple> temp;

    if (!alias.compare(0, strlen(LAG_PREFIX), LAG_PREFIX))
    {
        if (m_stateLagTable.get(alias, temp))
        {
            SWSS_LOG_DEBUG("%s is ready", alias.c_str());
            return true;
        }
    }
    else if (m_statePortTable.get(alias, temp))
    {
        auto state_opt = swss::fvsGetValue(temp, "state", true);
        if (!state_opt)
        {
            return false;
        }
        SWSS_LOG_DEBUG("%s is ready", alias.c_str());
        return true;
    }
    SWSS_LOG_DEBUG("%s is not ready", alias.c_str());
    return false;
}

bool VlanMgr::isVlanStateOk(const string &alias)
{
    vector<FieldValueTuple> temp;

    if (!alias.compare(0, strlen(VLAN_PREFIX), VLAN_PREFIX))
    {
        if (m_stateVlanTable.get(alias, temp))
        {
            SWSS_LOG_DEBUG("%s is ready", alias.c_str());
            return true;
        }
    }
    SWSS_LOG_DEBUG("%s is not ready", alias.c_str());
    return false;
}

bool VlanMgr::isVlanMemberStateOk(const string &vlanMemberKey)
{
    vector<FieldValueTuple> temp;

    if (m_stateVlanMemberTable.get(vlanMemberKey, temp))
    {
        SWSS_LOG_DEBUG("%s is ready", vlanMemberKey.c_str());
        return true;
    }
    return false;
}

/*
 * members is grouped in format like
 * "Ethernet1,Ethernet2,Ethernet3,Ethernet4,Ethernet5,Ethernet6,
 * Ethernet7,Ethernet8,Ethernet9,Ethernet10,Ethernet11,Ethernet12,
 * Ethernet13,Ethernet14,Ethernet15,Ethernet16,Ethernet17,Ethernet18,
 * Ethernet19,Ethernet20,Ethernet21,Ethernet22,Ethernet23,Ethernet24"
 */
void VlanMgr::processUntaggedVlanMembers(string vlan, const string &members)
{

    auto consumer_it = m_consumerMap.find(CFG_VLAN_MEMBER_TABLE_NAME);
    if (consumer_it == m_consumerMap.end())
    {
        SWSS_LOG_ERROR("Failed to find tableName:%s", CFG_VLAN_MEMBER_TABLE_NAME);
        return;
    }
    auto& consumer = static_cast<Consumer &>(*consumer_it->second);

    vector<string> vlanMembers = tokenize(members, ',');

    for (auto vlanMember : vlanMembers)
    {
        string member_key = vlan + CONFIGDB_KEY_SEPARATOR + vlanMember;

        /* Directly put it into consumer.m_toSync map */
        if (consumer.m_toSync.find(member_key) == consumer.m_toSync.end())
        {
            vector<FieldValueTuple> fvVector;
            FieldValueTuple t("tagging_mode", "untagged");
            fvVector.push_back(t);
            KeyOpFieldsValuesTuple tuple = make_tuple(member_key, SET_COMMAND, fvVector);
            consumer.addToSync(tuple);
            SWSS_LOG_DEBUG("%s", (consumer.dumpTuple(tuple)).c_str());
        }
        /*
         * There is pending task from consumer pipe, in this case just skip it.
         */
        else
        {
            SWSS_LOG_WARN("Duplicate key %s found in table:%s", member_key.c_str(), CFG_VLAN_MEMBER_TABLE_NAME);
            continue;
        }
    }

    doTask(consumer);
    return;
}

void VlanMgr::doVlanMemberTask(Consumer &consumer)
{
    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        auto &t = it->second;

        string key = kfvKey(t);

        /* Ensure the key starts with "Vlan" otherwise ignore */
        if (strncmp(key.c_str(), VLAN_PREFIX, 4))
        {
            SWSS_LOG_ERROR("Invalid key format. No 'Vlan' prefix: %s", key.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        key = key.substr(4);
        size_t found = key.find(CONFIGDB_KEY_SEPARATOR);
        int vlan_id;
        string vlan_alias, port_alias;
        if (found != string::npos)
        {
            vlan_id = stoi(key.substr(0, found));
            port_alias = key.substr(found+1);
        }
        else
        {
            SWSS_LOG_ERROR("Invalid key format. No member port is presented: %s",
                           kfvKey(t).c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        vlan_alias = VLAN_PREFIX + to_string(vlan_id);
        string op = kfvOp(t);

       // TODO:  store port/lag/VLAN data in local data structure and perform more validations.
        if (op == SET_COMMAND)
        {
             if (isVlanMemberStateOk(kfvKey(t)))
             {
                SWSS_LOG_DEBUG("%s already set", kfvKey(t).c_str());
                m_vlanMemberReplay.erase(kfvKey(t));
                it = consumer.m_toSync.erase(it);
                continue;
             }

            /* Don't proceed if member port/lag is not ready yet */
            if (!isMemberStateOk(port_alias) || !isVlanStateOk(vlan_alias))
            {
                SWSS_LOG_DEBUG("%s not ready, delaying", kfvKey(t).c_str());
                it++;
                continue;
            }
            string tagging_mode = "untagged";

            for (auto i : kfvFieldsValues(t))
            {
                if (fvField(i) == "tagging_mode")
                {
                    tagging_mode = fvValue(i);
                }
            }

            if (tagging_mode != "untagged" &&
                tagging_mode != "tagged"   &&
                tagging_mode != "priority_tagged")
            {
                SWSS_LOG_ERROR("Wrong tagging_mode '%s' for key: %s", tagging_mode.c_str(), kfvKey(t).c_str());
                it = consumer.m_toSync.erase(it);
                continue;
            }

            if (addHostVlanMember(vlan_id, port_alias, tagging_mode))
            {
                key = VLAN_PREFIX + to_string(vlan_id);
                key += DEFAULT_KEY_SEPARATOR;
                key += port_alias;
                m_appVlanMemberTableProducer.set(key, kfvFieldsValues(t));

                vector<FieldValueTuple> fvVector;
                FieldValueTuple s("state", "ok");
                fvVector.push_back(s);
                m_stateVlanMemberTable.set(kfvKey(t), fvVector);

                m_vlanMemberReplay.erase(kfvKey(t));
            }
        }
        else if (op == DEL_COMMAND)
        {
            if (isVlanMemberStateOk(kfvKey(t)))
            {
                removeHostVlanMember(vlan_id, port_alias);
                key = VLAN_PREFIX + to_string(vlan_id);
                key += DEFAULT_KEY_SEPARATOR;
                key += port_alias;
                m_appVlanMemberTableProducer.del(key);
                m_stateVlanMemberTable.del(kfvKey(t));
            }
            else
            {
                SWSS_LOG_DEBUG("%s doesn't exist", kfvKey(t).c_str());
            }
            SWSS_LOG_DEBUG("%s", (consumer.dumpTuple(t)).c_str());
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation type %s", op.c_str());
        }
        /* Other than the case of member port/lag is not ready, no retry will be performed */
        it = consumer.m_toSync.erase(it);
    }
    if (!replayDone && m_vlanMemberReplay.empty() &&
        WarmStart::isWarmStart())
    {
        replayDone = true;
        WarmStart::setWarmStartState("vlanmgrd", WarmStart::REPLAYED);
        SWSS_LOG_NOTICE("vlanmgr warmstart state set to REPLAYED");
        WarmStart::setWarmStartState("vlanmgrd", WarmStart::RECONCILED);
        SWSS_LOG_NOTICE("vlanmgr warmstart state set to RECONCILED");

    }
}
bool VlanMgr::setNetdevNeighSuppress(const string &netdev, const string &suppress_mode)
{
    SWSS_LOG_ENTER();

    // The command should be generated as:
    // /bin/bash -c "echo {"0"| "1"} > /sys/devices/virtual/net/vtep-1000/brport/neigh_suppress"
    if (suppress_mode == "on")
    {
        ostringstream cmds, inner;
        inner << ECHO_CMD << " " << shellquote("1") << " >> /sys/devices/virtual/net/" + netdev + "/brport/neigh_suppress";
        cmds << BASH_CMD " -c " << shellquote(inner.str());

        std::string res;
        int ret = swss::exec(cmds.str(), res);
        if (ret)
        {
            SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmds.str().c_str(), ret);
        }

        if (!setNftRule(NFT_ARP_CHAIN, netdev, true)
            || !setNftRule(NFT_VLAN_ARP_CHAIN, netdev, true)
            || !setNftRule(NFT_ND_CHAIN, netdev, true))
        {
            SWSS_LOG_ERROR("failed to set nftables rules");
            return false;
        }
    }
    else
    {
        ostringstream cmds, inner;

        // check the vtep netdev folder  is existed or not
        if (access(("/sys/devices/virtual/net/" + netdev).c_str(), F_OK) == 0)
        {
            inner << ECHO_CMD << " " << shellquote("0") << " >> /sys/devices/virtual/net/" + netdev + "/brport/neigh_suppress";
            cmds << BASH_CMD " -c " << shellquote(inner.str());

            std::string res;
            int ret = swss::exec(cmds.str(), res);
            if (ret)
            {
                SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmds.str().c_str(), ret);
            }
        }
        else
        {
            SWSS_LOG_INFO("netdev %s is not existed, ignore to set neigh_suppress", netdev.c_str());
        }

        if (!setNftRule(NFT_ARP_CHAIN, netdev, false)
            || !setNftRule(NFT_VLAN_ARP_CHAIN, netdev, false)
            || !setNftRule(NFT_ND_CHAIN, netdev, false))
        {
            SWSS_LOG_ERROR("failed to set nftables rules");
            return false;
        }
    }

    return true;
}

void VlanMgr::doNeighSuppressTask(Consumer &consumer)
{
    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        // skip neigh-suppression since orchagent and sai is not ready
        {
            it = consumer.m_toSync.erase(it);
            continue;
        }

        auto &t = it->second;

        string key = kfvKey(t);
        string vlan_alias;
        string netdev;
        /* Ensure the key starts with "Vlan" otherwise ignore */
        if (strncmp(key.c_str(), VLAN_PREFIX, 4))
        {
            SWSS_LOG_ERROR("Invalid key format. No 'Vlan' prefix: %s", key.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }
        vlan_alias = key;
        vector<FieldValueTuple> values;
        string op = kfvOp(t);

        if (m_stateNeighSuppressVlanTable.get(vlan_alias, values))
        {
            SWSS_LOG_INFO("m_stateNeighSuppressVlanTable.get ok");
            auto isNetDevField = [](FieldValueTuple fv) { return fvField(fv) == "netdev"; };
            auto valueIt = std::find_if(values.begin(), values.end(), isNetDevField);

            if (valueIt != values.end())
            {
                netdev = fvValue(*valueIt);
            }
            else
            {
                it = consumer.m_toSync.erase(it);
                continue;
            }
        }
        else
        {
            SWSS_LOG_INFO("Failed to get entry in m_stateNeighSuppressVlanTable for vlan %s", vlan_alias.c_str());
            ++it;
            continue;
        }

        string suppress_mode = "off"; //default value for "suppress" field

        if (op == SET_COMMAND)
        {
            for (auto i : kfvFieldsValues(t))
            {
                if (fvField(i) == "suppress")
                {
                    suppress_mode = fvValue(i);
                    break;
                }
            }
        }
        else if (op == DEL_COMMAND)
        {
            suppress_mode = "off";
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation type %s", op.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        if (suppress_mode != "on" &&
            suppress_mode != "off")
        {
            SWSS_LOG_ERROR("Wrong suppress_mode '%s' for key: %s", suppress_mode.c_str(), kfvKey(t).c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        try
        {
            if (setNetdevNeighSuppress(netdev, suppress_mode))
            {
                SWSS_LOG_INFO("setNetdevNeighSuppress %s mode: %s ok", netdev.c_str(), suppress_mode.c_str());
                key = vlan_alias;

                // Update Vlan member in ARP/ND nftables rules
                vector<string> vlanMemberKeys;
                m_cfgVlanMemberTable.getKeys(vlanMemberKeys);
                for (auto key: vlanMemberKeys)
                {
                    size_t delimeter = key.find(CONFIGDB_KEY_SEPARATOR);
                    if (delimeter != string::npos)
                    {
                        string vlan_str = key.substr(0, delimeter);
                        if (!vlan_str.compare(vlan_alias))
                        {
                            string port_str = key.substr(delimeter+1);
                            int vlan_id;
                            try
                            {
                                vlan_id = stoi(key.substr(4));
                            }
                            catch (...)
                            {
                                SWSS_LOG_ERROR("Invalid key format. Not a number after 'Vlan' prefix: %s", key.c_str());
                                continue;
                            }

                            if (op == SET_COMMAND)
                            {
                                updateVlanMemberNftRule(vlan_id, port_str, true);
                            }
                            else if (op == DEL_COMMAND)
                            {
                                updateVlanMemberNftRule(vlan_id, port_str, false);
                            }
                        }
                    }
                }

                if (op == SET_COMMAND)
                {
                    m_appNeighSuppressVlanTableProducer.set(key, kfvFieldsValues(t));
                }
                else if (op == DEL_COMMAND)
                {
                    m_appNeighSuppressVlanTableProducer.del(key);
                }
            }
            else
            {
                SWSS_LOG_ERROR("setNetdevNeighSuppress %s mode %s fail", netdev.c_str(), suppress_mode.c_str());
                ++it;
                continue;
            }
        }
        catch (const std::exception &e)
        {
            SWSS_LOG_ERROR("setNetdevNeighSuppress %s mode %s fail. msg: %s", netdev.c_str(), suppress_mode.c_str(), e.what());
            ++it;
            continue;
        }

        it = consumer.m_toSync.erase(it);
    }
}
void VlanMgr::doNeighSuppressVlanTask(Consumer &consumer)
{
    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        // skip neigh-suppression since orchagent and sai is not ready
        {
            it = consumer.m_toSync.erase(it);
            continue;
        }

        auto &t = it->second;

        string key = kfvKey(t);
        string vlan_alias;
        string netdev;
        int vlan_id;
        /* Ensure the key starts with "Vlan" otherwise ignore */
        if (strncmp(key.c_str(), VLAN_PREFIX, 4))
        {
            SWSS_LOG_ERROR("Invalid key format. No 'Vlan' prefix: %s", key.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }
        vlan_alias = key;
        vlan_id = stoi(key.substr(4));
        string op = kfvOp(t);

        for (auto i : kfvFieldsValues(t))
        {
            if (fvField(i) == "netdev")
            {
                netdev = fvValue(i);
                break;
            }
        }

        if (op == SET_COMMAND)
        {
            string mode;
            vector<FieldValueTuple> values;
            m_cfgNeighSuppressVlanTable.get(vlan_alias, values);
            auto isSuppressField = [](FieldValueTuple fv) { return fvField(fv) == "suppress"; };
            auto valueIt = std::find_if(values.begin(), values.end(), isSuppressField);
            if (valueIt != values.end())
            {
                mode = fvValue(*valueIt);
                SWSS_LOG_INFO("suppress is %s", mode.c_str());
            }

            if (mode == "on" && netdev !="")
            {
                try
                {
                    if (setNetdevNeighSuppress(netdev, "on"))
                    {
                        SWSS_LOG_INFO("setNetdevNeighSuppress %s mode: %s ok", netdev.c_str(), mode.c_str());
                        key = vlan_alias;
                        vector<FieldValueTuple> fvVector;
                        FieldValueTuple suppress("suppress", "on");
                        fvVector.push_back(suppress);
                        m_appNeighSuppressVlanTableProducer.set(key, fvVector);
                        updateVlanMemberNftRule(vlan_id, true);
                        m_vlanVtepMap[vlan_id] = netdev;
                        it = consumer.m_toSync.erase(it);
                        continue;
                    }
                }
                catch (const std::exception &e)
                {
                    SWSS_LOG_ERROR("setNetdevNeighSuppress %s mode %s fail. msg: %s", netdev.c_str(), mode.c_str(), e.what());
                }
            }
            else
            {
                removeVlanNeighborSuppression(vlan_id);
                m_appNeighSuppressVlanTableProducer.del(key);
                m_vlanVtepMap.erase(vlan_id);
                it = consumer.m_toSync.erase(it);
                continue;
            }
        }
        else if (op == DEL_COMMAND)
        {
            removeVlanNeighborSuppression(vlan_id);
            m_appNeighSuppressVlanTableProducer.del(key);
            m_vlanVtepMap.erase(vlan_id);
            it = consumer.m_toSync.erase(it);
            continue;
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation type %s", op.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

    }
}
void VlanMgr::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    string table_name = consumer.getTableName();

    if (table_name == CFG_VLAN_TABLE_NAME)
    {
        doVlanTask(consumer);
    }
    else if (table_name == CFG_VLAN_MEMBER_TABLE_NAME)
    {
        doVlanMemberTask(consumer);
    }
    else if (table_name == CFG_NEIGH_SUPPRESS_VLAN_TABLE_NAME)
    {
        SWSS_LOG_DEBUG("Table:CFG_NEIGH_SUPPRESS_VLAN_TABLE_NAME");
        doNeighSuppressTask(consumer);
    }
    else if (table_name == STATE_NEIGH_SUPPRESS_VLAN_TABLE_NAME)
    {
        SWSS_LOG_DEBUG("Table:STATE_NEIGH_SUPPRESS_VLAN_TABLE_NAME");
        doNeighSuppressVlanTask(consumer);
    }
    else
    {
        SWSS_LOG_ERROR("Unknown config table %s ", table_name.c_str());
        throw runtime_error("VlanMgr doTask failure.");
    }
}

void VlanMgr::removeVlanNeighborSuppression(int vlan_id)
{
    SWSS_LOG_ENTER();

    if (m_vlanVtepMap.find(vlan_id) != m_vlanVtepMap.end())
    {
        auto vtep_name = m_vlanVtepMap[vlan_id];
        setNetdevNeighSuppress(vtep_name, "off");
        m_vlanVtepMap.erase(vlan_id);
    }
    else
    {
        SWSS_LOG_INFO("vlan_id %d not exist in m_vlanVtepMap, ingore to off neigh_suppress", vlan_id);
    }

    SWSS_LOG_INFO("remove nftables rules for vlan %d", vlan_id);
    updateVlanMemberNftRule(vlan_id, false);
}


