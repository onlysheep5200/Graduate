from mininet.topo import Topo
class MyTopo(Topo):
    '''my topo'''
    def __init__(self):
        Topo.__init__(self)
        leftHost = self.addHost('h1')
        rightHost = self.addHost('h2')
        leftHost1 = self.addHost('h3')
        rightHost2 = self.addHost('h4')
        leftSwitch = self.addSwitch('s3')
        rightSwitch = self.addSwitch('s4')

        self.addLink(leftHost,leftSwitch,bw=10)
        self.addLink(leftHost1,leftSwitch,bw=10)
        self.addLink(leftSwitch,rightSwitch,bw=10,delay='100ms')
        self.addLink(rightSwitch,rightHost,bw=10)
        self.addLink(rightSwitch,rightHost2,bw=10)

topos = {'mytopo':(lambda : MyTopo())}
