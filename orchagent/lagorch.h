#ifndef SWSS_LAGORCH_H
#define SWSS_LAGORCH_H

#include "orch.h"
#include "port.h"
#include "portsorch.h"

#include <map>

using namespace std;
using namespace swss;

typedef map<string, set<string>> LagTable;

class LagOrch : public Orch
{
public:
    LagOrch(DBConnector *db, string tableName, PortsOrch *portsOrch) :
        Orch(db, tableName), m_portsOrch(portsOrch) {};

private:
    void doTask(Consumer &consumer);

    bool addLag(string lag);
    bool removeLag(Port lag);
    bool addLagMember(Port port, Port lag);
    bool removeLagMember(Port port, Port lag);

    PortsOrch *m_portsOrch;
    LagTable m_lags;
};

#endif /* SWSS_LAGORCH_H */
