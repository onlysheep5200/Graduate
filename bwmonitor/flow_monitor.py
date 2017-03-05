from __future__ import division
from ryu import cfg
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet,arp,ethernet
import networkx as nx
import time
import setting
import logging
from collections import namedtuple
import redis
import json
from ryu.lib import hub
import random
import event


CONF = cfg.CONF

LOG = logging.getLogger(__name__)

redis_client = redis.StrictRedis(**setting.REDIS_CONFIG)

# A pure arp proxy
# By the way record the flow info to DB
class FlowMonitor(app_manager.RyuApp):
    """
        NetworkDelayDetector is a Ryu app for collecting link delay.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(FlowMonitor, self).__init__(*args, **kwargs)
        self._topo_module = lookup_service_brick("topoaware")
        self._route_module = None
        self.name = "flow_monitor"
        self.history_packets = {}
        self.thread_for_flow = {}
        self.dump_flow_thread = hub.spawn(self._dump_flow_info)


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        flows = self.route_module.flows if self.route_module else None
        if not flows:
            return
        for stat in ev.msg.body:
            match = stat.match
            match_str = str(match)
            if match_str not in self.history_packets:
                self.history_packets[match_str] = {
                    datapath.id : stat
                }
            elif datapath.id not in self.history_packets[match_str] :
                self.history_packets[match_str][datapath.id] = stat
            else :
                pre_stat = self.history_packets[match_str][datapath.id]
                speed = self._get_speed(stat.byte_count,pre_stat.byte_count,
                                        self._get_period(stat.duration_sec,stat.duration_nsec,pre_stat.duration_sec,
                                                         pre_stat.duration_nsec))
                flow = flows.get(match_str)
                if flow:
                    flow.speed = speed/1024/1000*8
                    if flow.speed == 0:
                        flow.zero_time += 1
                        #speed is zero after threshold
                        if flow.zero_time > setting.FLOW_REMOVE_THRESHOLD : 
                            self.remove_flow_table_item(flow,match)
                            flow.path.flow_remove(flow)
                            del flows[match_str]
                self.history_packets[match_str][datapath.id] = stat

    #monitor flow removed notification
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            self.logger.info('flow removed : %s', str(msg.match))
            match = msg.match
            key = str(match)
            if self.route_module:
                try:
                    if key in self.route_module.flows:
                        flow = self.route_module.flows[key]
                        if flow.path :
                            flow.path.flow_remove(flow)
                        flow = None
                        del self.route_module.flows[key]
                        self.logger.info('flow with match %s has been removed',key)
                        self._dump_flow_info()
                except Exception,e:
                    self.logger.warn('rotue module not in flows')
                    print e



    @property
    def topo_module(self):
        if not self._topo_module:
            self._topo_module = lookup_service_brick('topoaware')
        return self._topo_module

    @property
    def route_module(self):
        if not self._route_module:
            self._route_module = lookup_service_brick('route_caculator')
        return self._route_module

    def flow_add(self,flow):
        self.thread_for_flow[flow.match] = hub.spawn(self.detector_generator(flow))

    def remove_flow_table_item(self,flow,match):
        path = flow.path
        pass

    def detector_generator(self,flow):
        def _detector() :
            while True :
                datapaths = self.topo_module.datapaths
                nodes = flow.path.nodes
                match = flow.match
                for node in nodes :
                    dp = datapaths[node.dpid]
                    ofp = dp.ofproto
                    ofp_parser = dp.ofproto_parser
                    cookie = cookie_mask = 0
                    req = ofp_parser.OFPFlowStatsRequest(dp, 0,
                                                 ofp.OFPTT_ALL,
                                                 ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                 cookie, cookie_mask,
                                                 match)
                    dp.send_msg(req)
                    hub.sleep(random.randint(1,3))
                hub.sleep(2)
        self.history_packets[flow.match] = {}
        return _detector

    def _get_time(self, sec, nsec):
        return sec

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    def _get_speed(self,bytes,pre_bytes,period):
        return (bytes - pre_bytes) / period if period else 0

    def _dump_flow_info(self):
        while True:
            flows = self.route_module.flows if self.route_module else None
            if flows:
                flows = [f.to_dict() for f in flows.values()]
                redis_client.set('flows',json.dumps(flows))
            hub.sleep(2)


