
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

QoS = namedtuple("QoS","bandwidth loss latency")


CONF = cfg.CONF

FLOW_RECOG_STATE_PREPARE = 0
FLOW_RECOG_STATE_RECOGNIZED = 1

FLOW_PRIORITY_NORMAL = 0
FLOW_PRIORITY_PROTECT = 1
FLOW_PRIORITY_VIP = 2

PROTOCOL_UNKNOWN = 0
PROTOCOL_TCP = 1
PROTOCOL_UDP = 2

FLOW_STATE_ACTIVE = 1
FLOW_STATE_REMOVED = 2






class Flow(object) :
    #app -> ryu application
    #match - > openflow match for flow
    #source -> source dpid
    #target -> target dpid
    #transport_protocol -> PROTOCOL_TCP or PROTOCOL_UDP
    #qos -> the qos demand
    current_group_id = 1
    id_gen_lock = Lock()
    def __init__(self,app,match,source,target,transport_protocol,qos = None):
        self.app = app
        self.match = match # initial match
        self.source_dp_id = source
        self.target_dp_id = target
        self.path = None
        self.speed = 0.0
        self.loss = 0.0
        self.occur_timestamp = time.time()
        self.recog_state = FLOW_RECOG_STATE_PREPARE # prepare for application recognization
        self.transport_protocol = transport_protocol
        self.application_type = transport_protocol
        self.priority = FLOW_PRIORITY_NORMAL
        self.qos = qos
        self.qos_has_changed = False
        self.current_priority = 1
        self.state = FLOW_STATE_ACTIVE
        Flow.id_gen_lock.acquire()
        self.group_id = Flow.current_group_id
        Flow.current_group_id += 1
        Flow.id_gen_lock.release()

    def set_path(self,path):
        if path :
            self.path = path
            self.path.install(self)


class Path(object) :
    def __init__(self,graph,nodes):
        self.graph = graph
        self.edges = []
        self.nodes = nodes
        self.source = nodes[0]
        self.target = nodes[-1]
        for i in xrange(0,len(nodes)-1) :
            self.edges.append(graph[nodes[i]][nodes[i+1]])
        if self.edges :
            self.bandwidth = sorted(self.edges,lambda x,y : cmp(y['bandwidth'],x['bandwidth']))[0]['bandwidth']
            self.free_bandwidth = sorted(self.edges,lambda x,y : cmp(x['free'],y['free']))
        self.flows = {}
        self.flow_entries = {} # dpid -> [flow table entries]

    #TODO:path with single node should be handle
    def install(self,flow):
        if isinstance(flow,Flow) :
            match = flow.match
            app = flow.app
            for i in xrange(0,len(self.nodes)-1) :
                preNode = self.nodes[i-1] if i >0 else None
                node = self.nodes[i]
                nextNode = self.nodes[i+1]
                print 'prenode is ',preNode
                print 'node is ',node
                print 'next node is ',nextNode
                if preNode == None :
                    extrasActions = self._get_report_controller_action(app,node)
                    #extrasActions = []
                else :
                    extrasActions = []
                self._install_flow_entry(flow,preNode,node,nextNode,extra_actions=extrasActions)
            self.flows[match] = flow


    def _install_flow_entry(self,flow,preNode,node,nextNode,extra_actions = None):
        app = flow.app
        match = flow.match
        curEdge = self.graph[node][nextNode]
        out_port = curEdge['src_port']
        datapaths = self._get_datapaths(app)
        dp = datapaths[node.dpid]
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(out_port,
                                      ofproto.OFPCML_NO_BUFFER)]

        if flow.recog_state == FLOW_RECOG_STATE_PREPARE and node == self.source :
            all_actions = actions+extra_actions if extra_actions else actions
            buckets = []
            for action in all_actions :
                bucket = parser.OFPBucket(100,ofproto.OFPP_ANY,ofproto.OFPQ_ALL,[action])
                buckets.append(bucket)
            app.add_group(dp,ofproto.OFPGT_ALL,flow.group_id,buckets)
            flow_actions = [parser.OFPActionGroup(flow.group_id)]
            app.add_flow(dp,flow.current_priority,match,flow_actions)
        else :
            app.add_flow(dp,flow.priority,match,actions)

        if nextNode == self.target :
            print 'find end of the path',nextNode
            nextDp = datapaths[nextNode.dpid]
            ip_to_host = app.host_module.ip_to_host
            target_host = ip_to_host[match['ipv4_dst']]
            if target_host and target_host.dpid == nextDp.id:
                target_host_port = target_host.port_no
                print 'target host port is %s'%str(target_host_port)
                actions = [parser.OFPActionOutput(target_host_port,
                                      ofproto.OFPCML_NO_BUFFER)]
                app.add_flow(nextDp,flow.current_priority,match,actions)

    def _get_report_controller_action(self,app,node):
        datapaths = self._get_datapaths(app)
        dp = datapaths[node.dpid]
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                      ofproto.OFPCML_NO_BUFFER)]
        return actions

    def _get_datapaths(self,app):
        if not hasattr(app,'datapaths') or not app.datapaths:
            datapaths = lookup_service_brick("topoaware").datapaths
            app.datapaths = datapaths
        else:
            datapaths = app.datapaths
        return datapaths

    def __str__(self):
        return self.nodes.__str__()


class RouterCaculator(app_manager.RyuApp):
    """
        NetworkDelayDetector is a Ryu app for collecting link delay.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RouterCaculator,self).__init__(*args,**kwargs)
        self._topo_module = None
        if self.topo_module :
            self.datapaths = self.topo_module.datapaths
        self.flows = {}
        self._host_module = None

    @property
    def topo_module(self):
        if not self._topo_module :
            self._topo_module = lookup_service_brick("topoaware")
        return self._topo_module

    @property
    def host_module(self):
        if not self._host_module :
            self._host_module = lookup_service_brick("hostaware")
        return self._host_module

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        match = msg.match
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        print eth.ethertype
        arp_pkt = get_protocol(pkt,arp.arp)
        if arp_pkt :
            #ignore arp packet
            return
        match = self.get_match(pkt,match,parser,ofproto)
        if not match :
            return

        if match not in self.flows :
            print match
            flow = self.create_flow(match,datapath)
            self.flows[match] = flow
            qos = self.get_flow_qos(match)
            if not qos :
                path = self.get_tmp_path_for_flow(flow)
                print 'tmp path',path
                self.send_to_application_recog(msg)
            else :
                flow.qos = qos
                path = self.get_init_path_for_flow(flow)
            flow.set_path(path)

        elif datapath.id == self.flows[match].source_dp_id :
            self.send_to_application_recog(msg)

        print match in self.flows

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self,ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            match = msg.match
            if self.flow_exists(match) :
                flow = self.flows[match]
                flow.state = FLOW_STATE_REMOVED
                flow_remove_event = event.EventOfFlowRemoved(flow)
                self.send_event_to_observers(flow_remove_event)




    def get_match(self,pkt,match,parser,proto):
        ip_pkt = get_protocol(pkt,ipv4.ipv4)
        if ip_pkt :
            #ignore DHCP
            if ip_pkt.src == '0.0.0.0' or ip_pkt.dst == '255.255.255.255':
                return None
            tcp_pkt = get_protocol(pkt,tcp.tcp)
            udp_pkt = get_protocol(pkt,udp.udp)
            icmp_pkt = get_protocol(pkt,icmp.icmp)
            ip_proto = ip_pkt.proto
            in_port = match['in_port']
            if tcp_pkt :
                pkt = tcp_pkt
                prefix = "tcp_"
            elif udp_pkt :
                pkt = udp_pkt
                prefix = "udp_"
            elif icmp_pkt :
                pkt = icmp_pkt
                prefix = None
            else :
                self.logger.info("UNSUPPORTED PROTOCOL")
                return None
            items = {}
            items['ip_proto'] = ip_proto
            items['eth_type'] = ether_types.ETH_TYPE_IP
            items['ipv4_src'] = ip_pkt.src
            items['ipv4_dst'] = ip_pkt.dst
            if prefix :
                items[prefix+'src'] = pkt.src_port
                items[prefix+'dst'] = pkt.dst_port
            match = parser.OFPMatch(**items)
            return match
        #TODO:IPV6 support
        return None

    def flow_exists(self,match):
        return match in self.flows

    #return flow object
    def create_flow(self,match,datapath):
        #get flow object according to source ip and target ip
        if not match :
            self.logger.error("match is none")
            return None

        graph = self.topo_module.graph
        ip_to_host = self.host_module.ip_to_host
        src_host = ip_to_host[match['ipv4_src']]
        dst_host = ip_to_host[match['ipv4_dst']]
        if not src_host or not dst_host :
            self.logger.error("host recognization error")
            return
        if match['ip_proto'] == 6 :
            transport_protocol = PROTOCOL_TCP
        elif match['ip_proto'] == 17 :
            transport_protocol = PROTOCOL_UDP
        else :
            transport_protocol = PROTOCOL_UNKNOWN
        flow = Flow(self,match,src_host.dpid,dst_host.dpid,transport_protocol)
        return flow







    #add flow entries
    def add_flow(self, datapath, priority, match, actions, buffer_id=None,idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,idle_timeout=idle_timeout,flags = ofproto.OFPFF_SEND_FLOW_REM)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,idle_timeout=idle_timeout,
                                    flags = ofproto.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod)

    #add group table
    def add_group(self,datapath,type,group_id,buckets):
        parser = datapath.ofproto_parser
        req = parser.OFPGroupMod(
                datapath, datapath.ofproto.OFPFC_ADD,
                type, group_id, buckets)
        datapath.send_msg(req)

    def get_flow_qos(self, match):
        return None

    def get_tmp_path_for_flow(self, flow):
        graph = self.topo_module.graph
        src = get_link_node(flow.source_dp_id)
        dst = get_link_node(flow.target_dp_id)
        nodes = nx.shortest_path(graph,src,dst)
        path = Path(graph,nodes)
        return path


    def send_to_application_recog(self, msg):
        pass

    def get_init_path_for_flow(self, flow):
        pass




