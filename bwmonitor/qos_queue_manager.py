#-*- coding:utf-8 -*-
import subprocess
import shlex
import tornado.ioloop
import tornado.web
import tornado.gen
from tornado.concurrent import run_on_executor

'''
for mininet, ryu cannot create bridge object for datapath, so here build a service to create queue
'''

cmd_template = '''
ovs-vsctl set port %s qos=@newqos -- \
    --id=@newqos create qos type=linux-htb \
      other-config:max-rate=1000000000 \
      queues:%d=q%d \
  --id=@q%d create queue other-config:min-rate=%d other-config:max-rate=%d
'''
# port_name -> last_queue_id
last_id_for_port = {}

# port_name -> [
#   {
#      uuid : 'uuid for queue',
#      id : 1  
#   }
# ]
# queues = {}


import tornado.ioloop
import tornado.web

from concurrent.futures import ThreadPoolExecutor

class MainHandler(tornado.web.RequestHandler):
    '''
    A handler help to create queues
    '''

    executor = ThreadPoolExecutor(20)

    #initialize a handler
    def initialize(self):
        self.queues = {}


    @tornado.gen.coroutine
    def get(self):
        '''
        get arguments : 
            port_name [str] port name 
            queue_id  [int] queue id
            min_rate  [int] min rate limit of the queue
            max_rate  [int] max rate limit of the queue
        '''
        port_name = self.get_argument("port_name",default="")
        queue_id = int(self.get_argument("queue_id"))
        min_rate = int(self.get_argument("min_rate",default=0))
        max_rate = int(self.get_argument("max_rate",default=0))
        yield self.create_qos_queue(port_name,queue_id,min_rate,max_rate)
        self.write({'status':0})

    @run_on_executor(executor = 'executor')
    def create_qos_queue(self,port_name,queue_id,min_rate=0,max_rate=1000000000):
        cmd = cmd_template%(port_name,queue_id,queue_id,queue_id,min_rate,max_rate)
        cmd = shlex.split(cmd)
        process = subporcess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
        stdout,stderror = process.communicate()
        self.queues.setdefault([])
        self.queues[port_name].append({
            'id':queue_id,
            'uuid':stdout.split('\n')[-1]
        })
    


def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(7788)
    tornado.ioloop.IOLoop.current().start()



