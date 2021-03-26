#ifndef __VLANMGR__
#define __VLANMGR__

#include "dbconnector.h"
#include "producerstatetable.h"
#include "orch.h"

#include <set>
#include <map>
#include <string>

namespace swss {

class VlanMgr : public Orch
{
public:
    VlanMgr(DBConnector *cfgDb, DBConnector *appDb, DBConnector *stateDb, const std::vector<TableConnector> &tables);
    using Orch::doTask;

private:
    ProducerStateTable m_appVlanTableProducer, m_appVlanMemberTableProducer;
    Table m_cfgVlanTable, m_cfgVlanMemberTable, m_cfgNeighSuppressVlanTable;
    Table m_statePortTable, m_stateLagTable, m_cfgSubInterfaceTable;
    Table m_stateVlanTable, m_stateVlanMemberTable;
    ProducerStateTable m_appNeighSuppressVlanTableProducer;
    Table m_stateNeighSuppressVlanTable;
    std::map<std::string, std::set<int>> m_neighborSuppressMap;
    std::map<int, std::string> m_vlanVtepMap;
    std::set<std::string> m_vlans;
    std::set<std::string> m_vlanReplay;
    std::set<std::string> m_vlanMemberReplay;
    bool replayDone;

    std::map<int, std::string> m_nftVlanMbrSetMap;
    std::map<std::string, std::map<std::string, std::string>> m_nftNdSpRuleHandles;
    std::map<int, std::set<std::string>> m_nftVlanMbrSetElement;
    void updateNftVlanMbrSetElement(int vlan_id, const std::string port_alias, std::string op);
    void updateNftVlanMbrSet(int vlan_id, bool is_set);

    void doTask(Consumer &consumer);
    void doVlanTask(Consumer &consumer);
    void doVlanMemberTask(Consumer &consumer);
    void doNeighSuppressTask(Consumer &consumer);
    void doNeighSuppressVlanTask(Consumer &consumer);
    bool setNetdevNeighSuppress(const std::string &netdev, const std::string &suppress_mode);
    void processUntaggedVlanMembers(std::string vlan, const std::string &members);

    bool addHostVlan(int vlan_id);
    bool removeHostVlan(int vlan_id);
    bool setHostVlanAdminState(int vlan_id, const std::string &admin_status);
    bool setHostVlanMtu(int vlan_id, uint32_t mtu);
    bool setHostVlanMac(int vlan_id, const std::string &mac);
    bool addHostVlanMember(int vlan_id, const std::string &port_alias, const std::string& tagging_mode);
    bool removeHostVlanMember(int vlan_id, const std::string &port_alias);
    bool isMemberStateOk(const std::string &alias);
    bool isVlanStateOk(const std::string &alias);
    bool isVlanMacOk();
    bool isVlanMemberStateOk(const std::string &vlanMemberKey);
    bool isSubportConfigVlan(const int vlan_id);
    bool isVlanNeighborSuppressed(int vlan_id);
    bool setNftRule(const std::string &chain_name, const std::string port_alias, bool is_add, int vlan_id = 0);
    void updateVlanMemberNftRule(int vlan_id, const std::string port_alias, bool is_add);
    void updateVlanMemberNftRule(int vlan_id, bool is_add);
    void removeVlanNeighborSuppression(int vlan_id);
};

}

#endif
