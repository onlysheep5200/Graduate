# -*- coding:utf-8 -*-
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
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

instance_name = "restful_api"

class RestfulApplication(app_manager.RyuApp):
    """
        NetworkDelayDetector is a Ryu app for collecting link delay.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = { 'wsgi': WSGIApplication }


    def __init__(self, *args, **kwargs):
        super(RestfulApplication, self).__init__(*args, **kwargs)
        self.name = 'restful'
        self.topo_module = lookup_service_brick("topoaware")
        wsgi = kwargs['wsgi']
        wsgi.register(RestfulController, {instance_name : self})



class RestfulController(ControllerBase) :
    def __init__(self, req, link, data, **config):
        super(RestfulController, self).__init__(req, link, data, **config)
        self.app = data[instance_name]
        self.persistent = self.app.persistent

    @route('get_topology', '/topology/getAll', methods=['GET'])
    def get_topology(self):
        pass



