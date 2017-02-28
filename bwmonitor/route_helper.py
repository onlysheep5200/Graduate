#-*- coding:utf-8 -*-
from collections import namedtuple
from threading import Lock
import time

'''
QoS : 
    bandwidth : bandwidth limit 
    loss : loss limit
    latency : latency limit 
    level :  
'''
QoS = namedtuple("QoS","bandwidth loss latency priority")

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

RECACULATE_FOR_RESOURCE_ADD = 1
RECACULATE_FOR_RESOURCE_DECREASE = 2

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
        self.application_type = 'unknown'
        self.priority = FLOW_PRIORITY_NORMAL
        self.qos = qos
        self.degree_time = 0
        self.current_priority = 1
        self.state = FLOW_STATE_ACTIVE
        Flow.id_gen_lock.acquire()
        self.group_id = Flow.current_group_id
        Flow.current_group_id += 1
        Flow.id_gen_lock.release()
        self.queue_id = 0
        self.degree_lock = Lock()
        self.first_data = None

    @property
    def is_degrade(self):
        return self.degree_time < 0

    def set_path(self,path):
        if path :
            self.path = path
            self.path.install(self)
            #LOG.info("path for flow : %s is %s"%(self.match,self.path))
    #TODO:concurrent
    def degrade(self):
        self.degree_lock.acquire()
        self.priority -= 1
        self.degree_time += 1
        self.degree_lock.release()
    #TODO:concurrent
    def upgrade(self):
        self.degree_lock.acquire()
        if self.degree_time <0:
            self.priority += 1
            self.degree_time -=1
        self.degree_lock.release()

    def to_dict(self):
        d = {
            'src_ip' : self.match['ipv4_src'],
            'dst_ip' : self.match['ipv4_dst'],
            'path' : str(self.path),
            'transport' : 'TCP' if self.transport_protocol == PROTOCOL_TCP else 'UDP',
            'app_type' : self.application_type,
            'speed' : self.speed,
            'priority' : self.priority,
            'bandwidth_need' : self.qos.bandwidth if self.qos else 'none',
            'latency_need' : self.qos.latency if self.qos else 'none'
        }
        if self.transport_protocol == PROTOCOL_TCP :
            d['src_port'] = self.match['tcp_src']
            d['dst_port'] = self.match['tcp_dst']
        elif self.transport_protocol == PROTOCOL_UDP :
            d['src_port'] = self.match['udp_src']
            d['dst_port'] = self.match['udp_dst']
        return d

class Path(object) :
    '''
    stand for a path in the network
    '''
    def __init__(self, graph, nodes):
        self.graph = graph
        self.nodes = nodes
        self.source = nodes[0]
        self.target = nodes[-1]
        self.latency = 0
        self.bandwidth = 0
        self.free_bandwidth = 0
        self.loss = 0
        self.inf = 0
        # for i in xrange(0,len(nodes)-1) :
        #     self.edges.append(graph[nodes[i]][nodes[i+1]])
        # if self.edges :
        #     self.bandwidth = sorted(self.edges,lambda x,y : cmp(y['bandwidth'],x['bandwidth']))[0]['bandwidth']
        #     self.free_bandwidth = sorted(self.edges,lambda x,y : cmp(x['free'],y['free']))
        self.flows = {}
        self.flow_entries = {} # dpid -> [flow table entries]
        self.qos_flow_exists = False
        self.update_attrs()

    def update_attrs(self):
        edges = self._get_edges()
        if edges :
            self.bandwidth = sorted(edges,lambda x,y : cmp(y['bandwidth'],x['bandwidth']))[0]['bandwidth']
            self.free_bandwidth = sorted(edges,lambda x,y : cmp(x['free'],y['free']))
            self.latency = sum([l['latency'] for l in edges])
            self.loss = reduce(lambda x,y : (1-x)*(1-y),[l['loss'] for l in edges],1)
            self.qos_flow_exists = len(filter(lambda x : x.priority > FLOW_PRIORITY_NORMAL,self.flows.values()))>0
            self.edges = edges
            self.inf = sorted(edges,lambda  x,y : cmp(y['inf'],x['inf']))[0]['inf']


    def meet_qos_for_flow(self,flow):
        if not flow.qos :
            return True
        qos = flow.qos
        if self.free_bandwidth >= qos.bandwidth and self.latency <= qos.latency :
            return True
        return False

    def meet_qos_for_exists_flows(self):
        qos_flows = [f for f in self.flows if not f.is_degrade]
        if qos_flows :
            free_now = self.free_bandwidth
            bandwidth_meet = reduce(lambda x,y : x-y,map(lambda f : f.qos.bandwidth,free_now),self.free_bandwidth) >= 0
            latency_meet = reduce(lambda x,y : x and y,[f.qos.latency >= self.latency for f in qos_flows])
            return bandwidth_meet and latency_meet
        return True

    def meet_qos_for_exists_flow(self,flow):
        if flow.priority <= FLOW_PRIORITY_NORMAL :
            return True
        if self.latency <= flow.qos.latency and self.free_bandwidth+flow.speed > flow.qos.bandwidth:
            return True
        return False



    #TODO:path with single node should be handle
    def install(self,flow):
        if isinstance(flow,Flow) :
            match = flow.match
            app = flow.app
            for i in xrange(0,len(self.nodes)-1) :
                preNode = self.nodes[i-1] if i >0 else None
                node = self.nodes[i]
                nextNode = self.nodes[i+1]
                # print 'prenode is ',preNode
                # print 'node is ',node
                # print 'next node is ',nextNode
                if preNode == None :
                    #extrasActions = self._get_report_controller_action(app,node)
                    extrasActions = []
                else :
                    extrasActions = []
                self._install_flow_entry(flow,preNode,node,nextNode,extra_actions=extrasActions)
            self._output_packet()

            self.flows[str(match)] = flow
            self.update_attrs()

    def flow_remove(self,flow):
        if str(flow.match) in self.flows and flow.path == self :
            match = flow.match
            edges = self._get_edges()
            for e in edges :
                e['flows'].remove(str(match))
            del self.flows[str(match)]


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
            app.add_flow(dp,flow.current_priority,match,actions)

        if nextNode == self.target :
            #print 'find end of the path',nextNode
            nextDp = datapaths[nextNode.dpid]
            ip_to_host = app.host_module.ip_to_host
            target_host = ip_to_host[match['ipv4_dst']]
            if target_host and target_host.dpid == nextDp.id:
                target_host_port = target_host.port_no
                print 'target host port is %s'%str(target_host_port)
                actions = [parser.OFPActionOutput(target_host_port,
                                      ofproto.OFPCML_NO_BUFFER)]
                app.add_flow(nextDp,flow.current_priority,match,actions)
        curEdge['flows'].append(str(match))
        self._caculate_edge_inf(app.flows,curEdge)

    def _caculate_edge_inf(self,flows,edge):
        flow_keys = edge['flows']
        flow_inf = 0
        for k in flow_keys :
            flow = flows[k]
            flow_inf += (10**flow.priority)*0.1
        edge['inf'] = flow_inf/(0.1*edge['free'])




    def _output_packet(self):
        pass

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

    def _get_edges(self):
        edges = []
        if self.graph :
            for i in xrange(0,len(self.nodes)-1) :
                edges.append(self.graph[self.nodes[i]][self.nodes[i+1]])
        return edges

    def __str__(self):
        dps = map(lambda x : str(x.dpid),self.nodes)
        return '->'.join(dps)

    def __eq__(self, other):
        return self.nodes.__eq__(other.nodes)