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
import logging
from collections import namedtuple
#from . import topology_awareness as topo_aware
import topology_awareness as topo_aware
import random


CONF = cfg.CONF

LOG = logging.getLogger(__name__)

PortSpeed = namedtuple('PortSpeed','tx_speed rx_speed version')

PortLoss = namedtuple('PortLoss','tx_loss rx_loss version')




class BandwidthDetector(app_manager.RyuApp):
    """
        BandwithDetector is a Ryu app for collecting bandwith.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(BandwidthDetector, self).__init__(*args, **kwargs)
        self.name = "bandwidthaware"
        self._topo_module = lookup_service_brick("topoaware")
        self.datapaths = {}
        self.last_port_stats = {} # (dpid,port_no) -> portstatsreply
        self.port_speed = {} # (dpid,port_no) -> speed
        self.port_loss = {} # (dpid,port_no) -> loss

        self.port_measure_thread = hub.spawn(self._port_stats_detect)



    @property
    def topo_module(self):
        if not self._topo_module :
            self._topo_module = lookup_service_brick('topoaware')
        return self._topo_module

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                LOG.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                LOG.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self,ev):
        dpid = ev.msg.datapath.id
        for stat in ev.msg.body :
            port_no = stat.port_no
            key = (dpid,port_no)
            last_rep = self.last_port_stats.get(key)
            if not last_rep :
                self.last_port_stats[key] = stat
                continue

            speed_version = self._get_version(self.port_speed,key)
            loss_version = self._get_version(self.port_loss,key)


            last_tx_bytes,last_rx_bytes,last_tx_packets,last_rx_packets,last_tx_dropped,last_rx_dropped\
            = last_rep.tx_bytes,last_rep.rx_bytes,last_rep.tx_packets,last_rep.rx_packets,last_rep.tx_dropped,\
              last_rep.rx_dropped

            tx_bytes,rx_bytes,tx_packets,rx_packets,tx_dropped,rx_dropped = stat.tx_bytes,stat.rx_bytes,stat.tx_packets,\
            stat.rx_bytes,stat.tx_dropped,stat.rx_dropped

            period = self._get_period(stat.duration_sec,stat.duration_nsec,last_rep.duration_sec,last_rep.duration_nsec)
            #print 'dp : %s,port %s ,now : %s, pre : %s'%(str(dpid),str(port_no),str(tx_bytes),str(last_rx_bytes))
            self.port_speed[(dpid,port_no)] = PortSpeed(tx_speed=self._get_speed(tx_bytes,last_tx_bytes,period),
                                                        rx_speed=self._get_speed(rx_bytes,last_rx_bytes,period),
                                                        version = speed_version+1)
            self.port_loss[(dpid,port_no)] = PortLoss(tx_loss = self._get_loss(tx_packets,tx_dropped,last_tx_packets,last_tx_dropped),
                                                      rx_loss = self._get_loss(rx_packets,rx_dropped,last_rx_packets,last_rx_dropped),
                                                      version = loss_version+1)
            self.update_graph(dpid,port_no)
            self.last_port_stats[key] = stat

    def update_graph(self,dpid,port_no):
        graph = self.topo_module.graph
        key = (dpid,port_no)
        src_speed = self.port_speed[key]
        src_loss = self.port_loss[key]
        if isinstance(graph,nx.Graph) :
            src = topo_aware.get_link_node(dpid)
            links = graph[src]
            for dst in links :
                dst_port = graph[src][dst]['dst_port']
                dst_key = (dst.dpid,dst_port)
                dst_speed = self.port_speed.get(dst_key)
                dst_loss = self.port_loss.get(dst_key)
                if src_speed and dst_speed:
                    # if src_speed.version == dst_speed.version :
                    #     used = min(src_speed.tx_speed,dst_speed.rx_speed)
                    # else :
                    #     used = src_speed.tx_speed if src_speed.version > dst_speed.version else dst_speed.rx_speed
                    used = self.get_real_speed(src_speed,dst_speed)
                    print 'current speed for %s:%s is %s'%(dpid,port_no,used)
                    graph[src][dst]['bandwidth_used'] = used
                    graph[src][dst]['free'] = graph[src][dst]['bandwidth'] - used
                    #used = min(src_speed.rx_speed,dst_speed.tx_speed)
                    used = self.get_real_speed(src_speed,dst_speed)
                    graph[dst][src]['bandwidth_used'] = used
                    graph[dst][src]['free'] = graph[dst][src]['bandwidth'] - used
                    graph[src][dst]['loss'] = self._get_link_loss(src_loss.tx_loss,dst_loss.rx_loss)
                    graph[dst][src]['loss'] = self._get_link_loss(dst_loss.tx_loss,src_loss.rx_loss)

    def get_real_speed(self,src_speed,dst_speed):
        if src_speed.version == dst_speed.version :
            used = max(src_speed.tx_speed,dst_speed.rx_speed)
        else :
            used = src_speed.tx_speed if src_speed.version > dst_speed.version else dst_speed.rx_speed
        return used*8/(1000*1024)






    def _port_stats_detect(self):
        while True :
            for _,dp in self.datapaths.iteritems() :
                ofp = dp.ofproto
                ofp_parser = dp.ofproto_parser
                ports = self.topo_module.dp_outward_port[dp.id]
                for p in ports :
                    portReq = ofp_parser.OFPPortStatsRequest(dp,port_no = p)
                    dp.send_msg(portReq)
                    hub.sleep(random.randint(1,3))

            hub.sleep(setting.PORT_STATS_DETECTING_PERIOD)


    def _get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    def _get_speed(self,bytes,pre_bytes,period):
        return (bytes - pre_bytes) / period if period else 0

    def _get_loss(self,packets,drops,pre_packets,pre_drops):
        return (drops - pre_drops) / (packets - pre_packets) if packets != pre_packets else 0

    def _get_version(self,keymap,key):
        if key not in keymap :
            return 0
        return keymap[key].version

    def _get_link_loss(self,tx_loss,rx_loss):
        return (1.0 - tx_loss)*(1.0-rx_loss)




