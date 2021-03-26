#include <unistd.h>
#include <vector>
#include <sstream>
#include <fstream>
#include <iostream>
#include <mutex>
#include <algorithm>
#include "dbconnector.h"
#include "select.h"
#include "exec.h"
#include "schema.h"
#include "macaddress.h"
#include "producerstatetable.h"
#include "vlanmgr.h"
#include "shellcmd.h"
#include "warm_restart.h"

using namespace std;
using namespace swss;

/* select() function timeout retry time, in millisecond */
#define SELECT_TIMEOUT 1000

MacAddress gMacAddress;

int main(int argc, char **argv)
{
    Logger::linkToDbNative("vlanmgrd");
    SWSS_LOG_ENTER();

    SWSS_LOG_NOTICE("--- Starting vlanmgrd ---");

    try
    {
        DBConnector cfgDb("CONFIG_DB", 0);
        DBConnector appDb("APPL_DB", 0);
        DBConnector stateDb("STATE_DB", 0);

        WarmStart::initialize("vlanmgrd", "swss");
        WarmStart::checkWarmStart("vlanmgrd", "swss");

        /*
         * swss service starts after interfaces-config.service which will have
         * switch_mac set.
         * Dynamic switch_mac update is not supported for now.
         */
        Table table(&cfgDb, "DEVICE_METADATA");
        std::vector<FieldValueTuple> ovalues;
        table.get("localhost", ovalues);
        auto it = std::find_if( ovalues.begin(), ovalues.end(), [](const FieldValueTuple& t){ return t.first == "mac";} );
        if ( it == ovalues.end() ) {
            throw runtime_error("couldn't find MAC address of the device from config DB");
        }
        gMacAddress = MacAddress(it->second);


        TableConnector conf_vlan_table(&cfgDb, CFG_VLAN_TABLE_NAME);
        TableConnector conf_vlan_member_table(&cfgDb, CFG_VLAN_MEMBER_TABLE_NAME);
        TableConnector conf_neigh_suppress_vlan_table(&cfgDb, CFG_NEIGH_SUPPRESS_VLAN_TABLE_NAME);
        TableConnector state_neigh_suppress_vlan_table(&stateDb, STATE_NEIGH_SUPPRESS_VLAN_TABLE_NAME);

        vector<TableConnector> tables = {
            conf_vlan_table,
            conf_vlan_member_table,
            conf_neigh_suppress_vlan_table,
            state_neigh_suppress_vlan_table
        };

        VlanMgr vlanmgr(&cfgDb, &appDb, &stateDb, tables);

        std::vector<Orch *> cfgOrchList = {&vlanmgr};

        swss::Select s;
        for (Orch *o : cfgOrchList)
        {
            s.addSelectables(o->getSelectables());
        }

        SWSS_LOG_NOTICE("starting main loop");
        while (true)
        {
            Selectable *sel;
            int ret;

            ret = s.select(&sel, SELECT_TIMEOUT);
            if (ret == Select::ERROR)
            {
                SWSS_LOG_NOTICE("Error: %s!", strerror(errno));
                continue;
            }
            if (ret == Select::TIMEOUT)
            {
                vlanmgr.doTask();
                continue;
            }

            auto *c = (Executor *)sel;
            c->execute();
        }
    }
    catch(const std::exception &e)
    {
        SWSS_LOG_ERROR("Runtime error: %s", e.what());
    }
    return -1;
}
