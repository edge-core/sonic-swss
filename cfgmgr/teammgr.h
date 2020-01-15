#pragma once

#include <set>
#include <string>

#include "dbconnector.h"
#include "netmsg.h"
#include "orch.h"
#include "producerstatetable.h"
#include <sys/types.h>

namespace swss {

class TeamMgr : public Orch
{
public:
    TeamMgr(DBConnector *cfgDb, DBConnector *appDb, DBConnector *staDb,
            const vector<TableConnector> &tables);

    using Orch::doTask;
    void cleanTeamProcesses(int signo);

private:
    Table m_cfgMetadataTable;   // To retrieve MAC address
    Table m_cfgPortTable;
    Table m_cfgLagTable;
    Table m_cfgLagMemberTable;
    Table m_statePortTable;
    Table m_stateLagTable;

    ProducerStateTable m_appPortTable;
    ProducerStateTable m_appLagTable;

    std::set<std::string> m_lagList;
    std::map<std::string, pid_t> m_lagPIDList;

    MacAddress m_mac;

    void doTask(Consumer &consumer);
    void doLagTask(Consumer &consumer);
    void doLagMemberTask(Consumer &consumer);
    void doPortUpdateTask(Consumer &consumer);

    task_process_status addLag(const string &alias, int min_links, bool fall_back);
    bool removeLag(const string &alias);
    task_process_status addLagMember(const string &lag, const string &member);
    bool removeLagMember(const string &lag, const string &member);

    bool setLagAdminStatus(const std::string &alias, const std::string &admin_status);
    bool setLagMtu(const std::string &alias, const std::string &mtu);
 
    pid_t getTeamPid(const std::string &alias);
    void addLagPid(const std::string &alias);
    void removeLagPid(const std::string &alias);

    bool isPortEnslaved(const string &);
    bool findPortMaster(string &, const string &);
    bool checkPortIffUp(const string &);
    bool isPortStateOk(const string&);
    bool isLagStateOk(const string&);
};

}
