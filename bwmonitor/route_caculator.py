#-*- coding:utf-8 -*-
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
import redis
import json
from route_helper import *
CONF = cfg.CONF
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

redis_client = redis.StrictRedis(**setting.REDIS_CONFIG)


class RouterCaculator(app_manager.RyuApp):
    """
        NetworkDelayDetector is a Ryu app for collecting link delay.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RouterCaculator,self).__init__(*args,**kwargs)
        self._topo_module = None
        self._flow_monitor = None
        if self.topo_module :
            self.datapaths = self.topo_module.datapaths
        self.flows = {}
        self.paths = set()
        self._host_module = None
        self.name = "route_caculator"
        self.route_cache = {} #(src_node,dst_node) -> [routes]
        #self.flow_dump_thread = hub.spawn(self._dump_flow_info)
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

    @property
    def flow_monitor(self):
        if self._flow_monitor == None :
            self._flow_monitor = lookup_service_brick('flow_monitor')
        return self._flow_monitor

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
        arp_pkt = get_protocol(pkt,arp.arp)
        if arp_pkt :
            #ignore arp packet
            return
        #print 'packet from datapath:%s port_no:%s'%(datapath.id,match['in_port'])
        match = self.get_match(pkt,match,parser,ofproto)
        if not match :
            return
        match_str = str(match)
        if match_str not in self.flows:
            #print match
            flow = self.create_flow(match,datapath)
            self.flows[match_str] = flow
            qos = self.get_flow_qos(match)
            if not qos :
                path = self.get_init_path_for_flow(flow)
                self.send_to_application_recog(msg)
            else:
                flow.qos = qos
                path = self.get_init_path_for_flow(flow)
            if not path :
                self.logger.error("no path for current flow from %s to %s"%(match['ipv4_src'],match['ipv4_dst']) )
                return
            self.logger.info('path for %s to %s is : %s,path inf is %s'%(match['ipv4_src'],match['ipv4_dst'],str(path),str(path.inf)))
            flow.set_path(path)
            self.paths.add(path)
            if self.flow_monitor :
                self.flow_monitor.flow_add(flow)

        elif datapath.id == self.flows[match_str].source_dp_id :
            self.send_to_application_recog(msg)




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
        src_port = ''
        dst_port = ''
        tsl = 'none'
        if not src_host or not dst_host :
            self.logger.error("host recognization error")
            return
        if match['ip_proto'] == 6 :
            transport_protocol = PROTOCOL_TCP
            src_port = match['tcp_src']
            dst_port = match['tcp_dst']
            tsl = 'TCP'
            
        elif match['ip_proto'] == 17 :
            transport_protocol = PROTOCOL_UDP
            src_port = match['udp_src']
            dst_port = match['udp_dst']
            tsl = 'UDP'
        else :
            #only tcp and udp packet need to add to flows
            transport_protocol = PROTOCOL_UNKNOWN
            tsl = 'none'
        flow = Flow(self,match,src_host.dpid,dst_host.dpid,transport_protocol)
        flow.application_type = get_application_type(match)

        #most accurate
        key = 'qos-'+str((unicode(match['ipv4_src']),unicode(match['ipv4_dst']),unicode(src_port),\
            unicode(dst_port),unicode(tsl),unicode(flow.application_type) if flow.application_type else unicode('none')))
        #print key
        qos = redis_client.get(key)
        if not qos :
            key = 'qos-'+str((unicode(match['ipv4_src']),unicode(match['ipv4_dst']),unicode(''),\
                unicode(''),unicode(tsl),unicode(flow.application_type) if flow.application_type else unicode('none')))
            qos = redis_client.get(key)
        print qos
        if qos :
            qos = json.loads(qos)
            flow_qos = QoS(qos['bandwidth'],qos['priority'],qos['max_rate'],qos['min_rate'],qos['latency'],qos.get('loss'))
            flow.qos = flow_qos
            flow.priority = flow.qos.priority
        else:
            flow.qos = None
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
                                    instructions=inst,idle_timeout=idle_timeout,flags = 1)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,idle_timeout=idle_timeout,
                                    flags = 1)
        datapath.send_msg(mod)

    def remove_flow(self,datapath,match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)


    #add group table
    def add_group(self,datapath,type,group_id,buckets):
        parser = datapath.ofproto_parser
        req = parser.OFPGroupMod(
                datapath, datapath.ofproto.OFPFC_ADD,
                type, group_id, buckets)
        datapath.send_msg(req)

    def get_flow_qos(self, match):
        key = "qos.%s"%str(match)
        content = redis_client.get(key)
        if content:
            try:
                qos = QoS(*json.loads(content))
                return qos
            except Exception,e :
                self.logger.error(e)
                return None
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
        #path = self._get_best_route_for_flow(flow)
        path = self._get_best_route_for_flow(flow)
        if path :
            return path
        else :
            #virtual reschedule
            return None

    '''
        callback :
            def callback(rs_type,p,recaculate_status = True,bandwidth_left = 0,changed_normal_flows=None,changed_qos_flows=None,degrade_flows=None,*args,**kwargs)
                .....
                return True or False
    '''
    def route_reschedule(self,path,trigger=RECACULATE_FOR_RESOURCE_DECREASE,callback = None):
        if trigger == RECACULATE_FOR_RESOURCE_ADD :
            pass
        else :
            qos_flows = [f for f in path.flows if f.priority == FLOW_PRIORITY_PROTECT]
            normal_flows = [f for f in path.flows if f.priority == FLOW_PRIORITY_NORMAL]
            bandwidth_need = reduce(lambda x,y : x.qos.bandwidth + y.qos.bandwidth,qos_flows)
            left = bandwidth_need - path.free_bandwidth
            bandwidth_for_normal = reduce(lambda x,y : x.speed + y.speed,normal_flows)
            if bandwidth_for_normal > left :
                return callback(recaculate_status = True,limit = left,changed_normal_flows=normal_flows)
            else :
                changed_qos_flows = []
                unchanged_qos_flows = []
                reduced_bandwidth = 0
                qos_flows = sorted(qos_flows,cmp = lambda x,y : cmp(x.qos.bandwidth,y.qos.bandwidth))
                for f in qos_flows :
                    new_path = self._get_best_route_for_flow(f)
                    if new_path != path :
                        changed_qos_flows.append(f)
                        left -= f.qos.bandwidth
                        if bandwidth_for_normal >= left :
                            return callback(True,left,normal_flows,changed_qos_flows)

                    else :
                        unchanged_qos_flows.append(f)
                flows_for_degrade = []
                for f in unchanged_qos_flows :
                    if left > bandwidth_for_normal :
                        flows_for_degrade.append(f)
                        left -= f.qos.bandwidth
                    else :
                        break
                return callback(True,left,normal_flows,changed_qos_flows,flows_for_degrade)

    def callback_for_reschedule(self,p,rs_type=RECACULATE_FOR_RESOURCE_DECREASE,recaculate_status = True,limit=0,changed_normal_flows=None,changed_qos_flows=None,degrade_flows=None):
        pass

    def callback_for_virtual_reschedule(self,path,rs_type=RECACULATE_FOR_RESOURCE_DECREASE,recaculate_status = True,bandwdith_left=0,changed_normal_flows=None,changed_qos_flows=None,degrade_flows=None,*args,**kwargs):
        if 'flow' not in kwargs:
            return
        flow = kwargs['flow']
        if rs_type == RECACULATE_FOR_RESOURCE_DECREASE and recaculate_status :
            if degrade_flows :
                return
            for f in changed_qos_flows :
                new_path = self._get_best_route_for_flow(flow)
                path.flow_remove(f)
                f.set_path(new_path)
            self.limit_speed_for_flows(changed_normal_flows,path,bandwdith_left)
            flow.set_path(path)
            path.update_attrs()



    def _install_path(self,flow,path=None):
        if not  path :
            path = self.get_init_path_for_flow(flow)
        if path :
            if flow.path :
                flow.path.flow_remove(flow)
            flow.set_path(path)
        else :
            #TODO:handle if without path
            return

    def limit_speed_for_flows(self,flows,path,speed=0):
        pass


    def _get_flows_meet_bandwidth(self,flows,bandwidth):
        pass

    def _get_best_route_for_flow(self,flow):
        graph = self.topo_module.graph
        src = get_link_node(flow.source_dp_id)
        dst = get_link_node(flow.target_dp_id)
        if (src,dst) in self.route_cache :
            raw_paths = self.route_cache[(src,dst)]
        else :
            raw_paths = nx.all_simple_paths(graph,src,dst)
            print raw_paths
            if not raw_paths :
                return None
        paths = []
        rps = []
        for rp in raw_paths :
            paths.append(Path(graph,rp))
            rps.append(rp)
        self.route_cache[(src,dst)] = rps
        paths = filter(lambda p : p.meet_qos_for_flow(flow),paths)

        if paths :
            paths = sorted(paths,cmp=lambda x,y : cmp(x.inf,y.inf))
            paths = filter(lambda x : x.inf == paths[0].inf,paths)
            paths = sorted(paths,cmp = lambda x,y : cmp(x.latency,y.latency))
            return paths[0]
        else :
            return None

    def _get_dijstra_route_for_flow(self,flow):
        graph = self.topo_module.graph
        src = get_link_node(flow.source_dp_id)
        dst = get_link_node(flow.target_dp_id)
        raw_path = nx.dijkstra_path(graph,src,dst)
        if raw_path :
            return Path(graph,raw_path)
        else :
            return None







