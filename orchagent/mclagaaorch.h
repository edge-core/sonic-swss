#ifndef __MCLAGAAORCH_H
#define __MCLAGAAORCH_H

#include "orch.h"
#include "portsorch.h"

class MclagAaOrch: public Orch
{
public:
    MclagAaOrch(DBConnector *appDb, DBConnector *stateDb, const std::vector<TableConnector> &connectors);
    void changeVlanMacAddress(string& vlanName, std::string mac);
    bool addVirtualRouterInterface(Port& vlan, std::string& mac);
    bool removeVirtualRouterInterface(Port& vlan);
    bool setMclagPeerlink(Port &port, bool is_peerlink);
    bool setMclagPeerlinkPort(sai_object_id_t m_port_id, bool is_peerlink);
    bool updateL3VniStatus(uint16_t vlan_id, bool isUp);
    std::string getMclagSystemMacAddress();

private:
    Table m_appMclagTable;
    Table m_stateMclagLocalIntfTable;
    map<string, string> peerlink_intf_name;
    void doTask(Consumer &consumer);
    void doPeerlinkTask(Consumer &consumer);
    void doPortIsolateTask(Consumer &consumer);
};

#endif // __MCLAGAAORCH_H
