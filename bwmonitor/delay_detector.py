from __future__ import division
from ryu import cfg
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology.switches import Switches
from ryu.topology.switches import LLDPPacket
import networkx as nx
import time
import setting
from ryu.topology import event
import random


CONF = cfg.CONF


class NetworkDelayDetector(app_manager.RyuApp):
    """
        NetworkDelayDetector is a Ryu app for collecting link delay.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkDelayDetector, self).__init__(*args, **kwargs)
        self.name = 'delaydetector'
        self.sending_echo_request_interval = 0.05
        # Get the active object of swicthes and awareness module.
        # So that this module can use their data.
        self.sw_module = lookup_service_brick('switches')
        #self.awareness = lookup_service_brick('awareness')

        self.datapaths = {}
        self.echo_latency = {}
        self.measure_thread = hub.spawn(self._detector)
        self.lldp_delays = {} # src -> dst -> delay
        self.link_delays = {} # src -> dst -> delay

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                self.link_delays[datapath.id] = {}
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Unregister datapath: %016x', datapath.id)
                del self.link_delays[datapath.id]
                del self.datapaths[datapath.id]

    def _detector(self):
        """
            Delay detecting functon.
            Send echo request and calculate link delay periodically
        """
        while True:
            self._send_echo_request()
            # self.create_link_delay()
            # try:
            #     self.awareness.shortest_paths = {}
            #     self.logger.debug("Refresh the shortest_paths")
            # except:
            #     self.awareness = lookup_service_brick('awareness')

            self.show_delay_statis()
            hub.sleep(setting.DELAY_DETECTING_PERIOD)

    def _send_echo_request(self):
        for datapath in self.datapaths.values():
            print self.sw_module.ports
            parser = datapath.ofproto_parser
            echo_req = parser.OFPEchoRequest(datapath,
                                             data="%.12f" % time.time())
            datapath.send_msg(echo_req)
            hub.sleep(random.randint(0,10))

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        now_timestamp = time.time()
        print 'echo reply accept'
        try:
            latency = now_timestamp - eval(ev.msg.data)
            self.echo_latency[ev.msg.datapath.id] = latency
        except:
            return

    def get_delay(self, src, dst):
        """
            Get link delay.
                        Controller
                        |        |
        src echo latency|        |dst echo latency
                        |        |
                   SwitchA-------SwitchB
                        
                    fwd_delay--->
                        <----reply_delay
            delay = (forward delay + reply delay - src datapath's echo latency
        """
        try:
            fwd_delay = self.lldp_delays[src][dst]
            re_delay = self.lldp_delays[dst][src]
            src_latency = self.echo_latency[src] if src in self.echo_latency else 0
            dst_latency = self.echo_latency[dst] if dst in self.echo_latency else 0
            
            delay = (fwd_delay + re_delay - src_latency - dst_latency)/2
            return max(delay, 0)
        except Exception,e:
            return float('inf')

    def _save_lldp_delay(self, src=0, dst=0, lldpdelay=0):
        if src not in self.lldp_delays:
            self.lldp_delays[src] = {}
        if src not in self.link_delays : 
            self.link_delays[src] = {}
        self.lldp_delays[src][dst] = lldpdelay
        delay = self.get_delay(src,dst)
        if delay > 0 : 
            self.link_delays[src][dst] = delay*1000


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
            Parsing LLDP packet and get the delay of link.
        """
        msg = ev.msg
        try:
            print 'lldp packet in '
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
            dpid = msg.datapath.id
            if self.sw_module is None:
                self.sw_module = lookup_service_brick('switches')

            for port in self.sw_module.ports.keys():
                if src_dpid == port.dpid and src_port_no == port.port_no:
                    delay = self.sw_module.ports[port].delay
                    #print '%s to %s delay : %s'%(str(src_dpid),str(dpid),str(delay))
                    self._save_lldp_delay(src=src_dpid, dst=dpid,
                                          lldpdelay=delay)
        except LLDPPacket.LLDPUnknownFormat as e:
            #print 'not lldp packet'
            return

    def show_delay_statis(self):
        #print "show"
        for src in self.link_delays : 
            print "%s -> : "%str(src)
            for dst in self.link_delays[src] : 
                print "    %s : %s"%(dst,self.link_delays[src][dst])

    def show_switches_delay(self):
        pass
        # if self.sw_module :
        #     for port in self.sw_module.ports.keys() :
                #print "pid : %s, port : %s, delay : %s"%(str(port.dpid),str(port.port_no),str(self.sw_module.ports[port].delay))

        