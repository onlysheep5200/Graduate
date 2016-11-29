from mininet.topo import Topo
import random
mapping = [
    [9,5,3,7],
    [9,5,4,8],
    [7,6,10],
    [8,6,10],
    [6],
    [],
    [8],
    [],
    [],
    []

]
host_mapping = {
    9:[2,1],
    1:[3],
    7:[6],
    3:[7],
    10:[9,10],
    4:[8],
    8:[5],
    2:[4]
}

bandwidth_mapping = {
    0 : {
        9 : 14,
        5 : 10,
        3 : 32,
        7 : 12
    },
    1 : {
        9 : 23,
        5 : 47,
        4 : 16,
        8 : 78,
    },
    2 : {
        7 : 55,
        6 : 71,
        10 : 9
    },
    3 : {
        8 : 11,
        6 : 32,
        10 : 88
    },
    4 : {
        6 : 34
    },
    6 : {
        8 : 66
    }
}
delays = {}
bandwidths = {}
class MyTopo(Topo):
    '''my topo'''
    def __init__(self):
        Topo.__init__(self)
        hosts = [self.addHost('h%d'%i) for i in range(1,11)]
        switches = [self.addSwitch('s%d'%i) for i in range(1,11)]
        for i in range(10) :
            if i+1 in host_mapping :
                for h in host_mapping[i+1] :
                    self.addLink(switches[i],hosts[h-1])
        for i in range(len(mapping)) :
            peers = mapping[i]
            for p in peers :
                #self.addLink(switches[i],switches[p-1],bw=bandwidths[i][p-1],delay='%dms'%delays[i][p-1])
                if i in bandwidth_mapping and p-1 in bandwidth_mapping[i]:
                    bw = bandwidth_mapping[i][p-1]
                else :
                    bw = bandwidth_mapping[p-1][i]
                self.addLink(switches[i],switches[p-1],bw=bw,delay='%dms'%random.randint(1,100))



topos = {'mytopo':(lambda : MyTopo())}
