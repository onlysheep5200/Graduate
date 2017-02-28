from mininet.topo import Topo
import random
class MyTopo(Topo):

    '''my topo'''
    def __init__(self):
        Topo.__init__(self)
        # hosts = [self.addHost('h%d'%i) for i in range(1,11)]
        # switches = [self.addSwitch('s%d'%i) for i in range(1,11)]
        # for i in range(10) :
        #     if i+1 in host_mapping :
        #         for h in host_mapping[i+1] :
        #             self.addLink(switches[i],hosts[h-1])
        # for i in range(len(mapping)) :
        #     peers = mapping[i]
        #     for p in peers :
        #         #self.addLink(switches[i],switches[p-1],bw=bandwidths[i][p-1],delay='%dms'%delays[i][p-1])
        #         if i in bandwidth_mapping and p in bandwidth_mapping[i]:
        #              bw = bandwidth_mapping[i][p]
        #         else :
        #              print '%d %d'%(i,p)
        #              bw = bandwidth_mapping[p-1][i+1]
        #         self.addLink(switches[i],switches[p-1],bw=bw,delay='%dms'%random.randint(1,50))
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        self.addLink(s1,h1)
        self.addLink(s1,h2)



topos = {'mytopo':(lambda : MyTopo())}
