from __future__ import division
from ryu import cfg
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.switches import LLDPPacket
import networkx as nx
import time
import setting
from collections import namedtuple
import logging
from ryu.topology.api import get_all_switch
import json

import redis
CONF = cfg.CONF

LOG = logging.getLogger(__name__)


LinkNode = namedtuple('LinkNode','dpid')

nodemap = {}


redis_client = redis.StrictRedis(host='127.0.0.1', port=6379, db=0)

def get_link_node(dpid):
    if dpid in nodemap :
        return nodemap[dpid]
    return LinkNode(dpid=dpid)





class TopoDetector(app_manager.RyuApp):
    """
        NetworkDelayDetector is a Ryu app for collecting link delay.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(TopoDetector, self).__init__(*args, **kwargs)
        self.name = 'topoaware'
        self.graph = nx.DiGraph()
        self.dp_outward_port = {}
        self.datapaths = {}
        self.ports_in_dp = {} # dpid -> port_no
        self.refresh_datapath_thread = hub.spawn(self.refresh_datapaths_view)
        self.dump_topo_thread = hub.spawn(self._dump_topo)
        self._host_module = None


    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self,ev):
        new_link = ev.link
        #assert new_link is None
        src_port = new_link.src.port_no
        dst_port = new_link.dst.port_no
        src = get_link_node(new_link.src.dpid)
        dst = get_link_node(new_link.dst.dpid)

        if src.dpid not in self.dp_outward_port :
            self.dp_outward_port[src.dpid] = []
        self.dp_outward_port[src.dpid].append(src_port)

        if dst.dpid not in self.dp_outward_port :
            self.dp_outward_port[dst.dpid] = []
        self.dp_outward_port[dst.dpid].append(dst_port)

        if not self.graph.has_node(src):
            self.graph.add_node(src)

        if not self.graph.has_node(dst):
            self.graph.add_node(dst)

        original_bandwidth = self._get_bandwidth(src.dpid,dst.dpid)

        self.graph.add_edge(src,dst,{'influence' : 0.0,'latency' : 0,'bandwidth' : original_bandwidth,'bandwidth_used' : 0,
                                     'loss' : 0, 'free': original_bandwidth,'src_port' : src_port,'dst_port' : dst_port,
                                     'flows' : [],'reserve':0})

        LOG.info("new link add : %s.%s -> %s.%s"%(src.dpid,src_port,dst.dpid,dst_port))



    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self,ev):
        deleted_link = ev.link
        src_port = deleted_link.src.port_no
        dst_port = deleted_link.dst.port_no
        src = get_link_node(deleted_link.src.dpid)
        dst = get_link_node(deleted_link.dst.dpid)

        if self.graph.has_edge(src,dst) :
            self.graph.remove_edge(src,dst)
        LOG.info("link deleted : %s.%s -> %s.%s"%(src.dpid,src_port,dst.dpid,dst_port))


    def refresh_datapaths_view(self):
        while True :
            hub.sleep(setting.DATAPATH_REFRESH_PERIOD)
            switches = get_all_switch(self)
            #LOG.info('switch num is %d'%len(switches))
            for sw in switches :
                dp = sw.dp
                if dp.id not in self.datapaths :
                    self.datapaths[dp.id] = dp
                ports = [p.port_no for p in sw.ports]
                self.ports_in_dp[dp.id] = set(ports)

    def get_edges(self,nodes):
        edges = []
        if self.graph :
            for i in xrange(0,len(nodes)-1) :
                edges.append(self.graph[nodes[i]][nodes[i+1]])
        return edges

    def _dump_topo(self):
        while True :
            result = {}
            if self.graph :
                for n1 in self.graph :
                    result.setdefault(n1.dpid,{})
                    for n2 in self.graph[n1] :
                        if n2.dpid in result and n1.dpid in result[n2.dpid] :
                            continue
                        result[n1.dpid][n2.dpid] = self.graph[n1][n2]
                redis_client.set('topo_for_switchs',json.dumps(result))
            hub.sleep(5)





    def _get_bandwidth(self,src_dp,dst_dp):
        return 10.0
#

