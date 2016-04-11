#ifndef SWSS_INTFSORCH_H
#define SWSS_INTFSORCH_H

#include "orch.h"
#include "portsorch.h"

#include "ipaddress.h"
#include "macaddress.h"

#include <map>

typedef map<string, IpAddress> IntfsTable;

class IntfsOrch : public Orch
{
public:
    IntfsOrch(DBConnector *db, string tableName, PortsOrch *portsOrch);
private:
    PortsOrch *m_portsOrch;
    IntfsTable m_intfs;
    void doTask(Consumer &consumer);
};

#endif /* SWSS_INTFSORCH_H */
