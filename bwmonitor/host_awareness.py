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


CONF = cfg.CONF

LOG = logging.getLogger(__name__)

Host = namedtuple('Host','ip mac port_no dpid')

hosts = {} # mac -> host

UNKNOWN_MAC = ['00:00:00:00:00:00','ff:ff:ff:ff:ff:ff']
UNKNOWN_IP = ['0.0.0.0']

def get_host(dpid,port_no,ip,mac) :
    if mac not in hosts :
        return Host(ip=ip,mac = mac,dpid = dpid,port_no = port_no)
    return hosts[mac]



# A pure arp proxy
class HostAwareness(app_manager.RyuApp):
    """
        NetworkDelayDetector is a Ryu app for collecting link delay.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(HostAwareness, self).__init__(*args, **kwargs)
        self.topo_module = lookup_service_brick("topoaware")
        self.name = "hostaware"
        self.ip_to_host = {} # ip -> host
        self.mac_to_host = {} # mac -> host

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        of_parser = dp.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        match = msg.match
        datapaths = self.topo_module.datapaths
        if eth and arp_pkt:
            src_mac = eth.src
            dst_mac = eth.dst
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            in_port = match['in_port']
            host = get_host(dp.id,in_port,src_ip,src_mac)
            self.logger.info("host with address : %s is link to switch %s in port %s"%(src_ip,str(dp.id),str(in_port)))

            if src_mac not in self.mac_to_host :
                self.mac_to_host[src_mac] = host
            if src_ip not in self.ip_to_host :
                self.ip_to_host[src_ip] = host

            if dst_mac not in UNKNOWN_MAC and dst_mac in self.mac_to_host :
                dst_host = self.mac_to_host[dst_mac]
            elif dst_ip not in UNKNOWN_IP and dst_ip in self.ip_to_host :
                dst_host = self.ip_to_host[dst_ip]
            else:
                dst_host = None

            #send to host directly
            if dst_host :
                dst_dp = datapaths.get(dst_host.dpid)
                if dst_dp :
                    actions = [of_parser.OFPActionOutput(dst_host.port_no)]
                    out = of_parser.OFPPacketOut(datapath=dst_dp,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                                  data=msg.data)
                    #TODO: choose a simple route for arp packet from src to dst
                    self.send_output_msg_to_datapath(dst_dp,dst_host.port_no,msg.data)
            #flood inner every datapath
            else :
                datapaths = self.topo_module.datapaths
                print datapaths
                for _,dp in datapaths.iteritems() :
                    outward_ports = self.topo_module.dp_outward_port[dp.id]
                    ports = self.topo_module.ports_in_dp[dp.id]
                    ports = [p for p in ports if p not in outward_ports]
                    self.send_output_msg_to_datapath(dp,ports,msg.data)


    def send_output_msg_to_datapath(self,dp,ports,data):
        of_parser = dp.ofproto_parser
        ofproto = dp.ofproto
        if not hasattr(ports,'__getitem__') :
            ports = [ports]
        actions = [of_parser.OFPActionOutput(p) for p in ports]
        out = of_parser.OFPPacketOut(datapath=dp,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                                  data=data)
        dp.send_msg(out)












