from swsscommon import swsscommon
import redis
import time
import os
import pytest
from pytest import *
import json
import re
from port_dpb import DPB

@pytest.mark.usefixtures('dpb_setup_fixture')
class TestPortDPB(object):

    '''
    |--------------------------------------------------
    |        | 1X100G | 1X40G | 4X10G | 4X25G | 2X50G |
    |--------------------------------------------------
    | 1X100G |   NA   |   P   |   P   |   P   |   P   |
    |--------------------------------------------------
    | 1X40G  |   P    |   NA  |   P   |   P   |       |
    |--------------------------------------------------
    | 4X10G  |   P    |   P   |   NA  |   P   |       |
    |--------------------------------------------------
    | 4X25G  |   P    |   P   |   P   |   NA  |       |
    |--------------------------------------------------
    | 2X50G  |   P    |       |       |       |   NA  |
    |--------------------------------------------------
    NA    --> Not Applicable
    P     --> Pass
    F     --> Fail
    Empty --> Not Tested
    '''

    '''
    @pytest.mark.skip()
    '''
    def test_port_breakout_one(self, dvs):
        dpb = DPB()
        dpb.breakout(dvs, "Ethernet0", 4)
        #print "**** 1X40G --> 4X10G passed ****"
        dpb.change_speed_and_verify(dvs, ["Ethernet0", "Ethernet1", "Ethernet2", "Ethernet3"], 25000)
        #print "**** 4X10G --> 4X25G passed ****"
        dpb.change_speed_and_verify(dvs, ["Ethernet0", "Ethernet1", "Ethernet2", "Ethernet3"], 10000)
        #print "**** 4X25G --> 4X10G passed ****"
        dpb.breakin(dvs, ["Ethernet0", "Ethernet1", "Ethernet2", "Ethernet3"])
        #print "**** 4X10G --> 1X40G passed ****"
        dpb.change_speed_and_verify(dvs, ["Ethernet0"], 100000)
        #print "**** 1X40G --> 1X100G passed ****"
        dpb.breakout(dvs, "Ethernet0", 4)
        #print "**** 1X100G --> 4X25G passed ****"
        dpb.change_speed_and_verify(dvs, ["Ethernet0", "Ethernet1", "Ethernet2", "Ethernet3"], 10000)
        #print "**** 4X25G --> 4X10G passed ****"
        dpb.change_speed_and_verify(dvs, ["Ethernet0", "Ethernet1", "Ethernet2", "Ethernet3"], 25000)
        #print "**** 4X10G --> 4X25G passed ****"
        dpb.breakin(dvs, ["Ethernet0", "Ethernet1", "Ethernet2", "Ethernet3"])
        #print "**** 4X25G --> 1X100G passed ****"
        dpb.breakout(dvs, "Ethernet0", 2)
        #print "**** 1X100G --> 2X50G passed ****"
        dpb.breakin(dvs, ["Ethernet0", "Ethernet2"])
        #print "**** 2X50G --> 1X100G passed ****"
        dpb.change_speed_and_verify(dvs, ["Ethernet0"], 40000)
        #print "**** 1X100G --> 1X40G passed ****"

    '''
    @pytest.mark.skip()
    '''
    def test_port_breakout_multiple(self, dvs):
        dpb = DPB()
        port_names = ["Ethernet0", "Ethernet12", "Ethernet64", "Ethernet112"]
        for pname in port_names:
            dpb.breakout(dvs, pname, 4)
        dpb.breakin(dvs, ["Ethernet0", "Ethernet1", "Ethernet2", "Ethernet3"])
        dpb.breakin(dvs, ["Ethernet12", "Ethernet13", "Ethernet14", "Ethernet15"])
        dpb.breakin(dvs, ["Ethernet64", "Ethernet65", "Ethernet66", "Ethernet67"])
        dpb.breakin(dvs, ["Ethernet112", "Ethernet113", "Ethernet114", "Ethernet115"])

    @pytest.mark.skip()
    def test_port_breakout_all(self, dvs):
        dpb = DPB()
        port_names = []
        for i in range(32):
            pname = "Ethernet" + str(i*4)
            port_names.append(pname)

        for pname in port_names:
            dpb.breakout(dvs, pname, 4)

        child_port_names = []
        for i in range(128):
            cpname = "Ethernet" + str(i)
            child_port_names.append(cpname)

        for i in range(32):
            start = i*4
            end = start+4
            dpb.breakin(dvs, child_port_names[start:end])
