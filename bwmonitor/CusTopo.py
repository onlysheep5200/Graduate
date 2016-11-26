from mininet.topo import Topo
import random
mapping = [
    [9,2,5,3,7],
    [9,5,4,8],
    [7,6,4,10],
    [8,6,10],
    [9,6],
    [10],
    [8],
    [],
    [],
    []

]
class MyTopo(Topo):
    '''my topo'''
    def __init__(self):
        Topo.__init__(self)
        # leftHost = self.addHost('h1')
        # rightHost = self.addHost('h2')
        # leftHost1 = self.addHost('h3')
        # rightHost2 = self.addHost('h4')
        # leftSwitch = self.addSwitch('s3')
        # rightSwitch = self.addSwitch('s4')
        #
        # self.addLink(leftHost,leftSwitch,bw=10)
        # self.addLink(leftHost1,leftSwitch,bw=10)
        # self.addLink(leftSwitch,rightSwitch,bw=10,delay='100ms')
        # self.addLink(rightSwitch,rightHost,bw=10)
        # self.addLink(rightSwitch,rightHost2,bw=10)
        hosts = [self.addHost('h%d'%i) for i in range(1,11)]
        switches = [self.addSwitch('s%d'%i) for i in range(1,11)]
        for i in range(10) :
            self.addLink(switches[i],hosts[i])
        for i in range(len(mapping)) :
            peers = mapping[i]
            for p in peers :
                self.addLink(switches[i],switches[p-1],bw=10,delay='%dms'%random.randint(0,100))



topos = {'mytopo':(lambda : MyTopo())}
