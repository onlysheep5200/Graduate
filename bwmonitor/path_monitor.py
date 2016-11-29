from __future__ import division
from ryu import cfg
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER,CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology.switches import Switches
from ryu.topology.switches import LLDPPacket
import networkx as nx
import time
import setting
from collections import namedtuple
from ryu.lib.packet import packet,ethernet,ether_types,arp,ipv4,tcp,udp
from utils import *
from ryu.lib.packet import icmp
from topology_awareness import get_link_node
import event
from threading import Lock

class RouterCaculator(app_manager.RyuApp):
    """
        NetworkDelayDetector is a Ryu app for collecting link delay.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RouterCaculator,self).__init__(*args,**kwargs)
        self._topo_module = None
        self._route_module = None
        self.update_thread = hub.spawn(self.caculate_path_attr)

    def caculate_path_attr(self):
        while True:
            if self.route_module and self.topo_module :
                paths = self.route_module.paths
                for path in paths :
                    path.update_attrs()

            hub.sleep(setting.PATH_ATTR_UPDATE_PERIOD)

    @property
    def topo_module(self):
        if not self._topo_module :
            self._topo_module = lookup_service_brick("topoaware")
        return self._topo_module

    @property
    def route_module(self):
        if not self._route_module :
            self._route_module = lookup_service_brick("route_caculator")
        return self._route_module
