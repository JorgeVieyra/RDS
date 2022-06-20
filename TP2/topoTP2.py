from mininet.topo import Topo

from mininet.net import Mininet

from mininet.node import Controller, RemoteController, OVSSwitch, UserSwitch, Node

from mininet.cli import CLI

from mininet.log import setLogLevel

from mininet.link import Link, TCLink

print ("Starting Mininet")
net = Mininet(controller = RemoteController, switch = OVSSwitch, autoSetMacs = False)

print ("Adding controllers")
c1 = net.addController('c1',controller=RemoteController,ip = '127.0.0.1',port=6633)
c2 = net.addController('c2',controller=RemoteController,ip = '127.0.0.1', port=6634)

s1 = net.addSwitch('s1',cls = OVSSwitch,dpid="0000000000000001")
s2 = net.addSwitch('s2',cls = OVSSwitch,dpid="0000000000000002")
s3 = net.addSwitch('s3',cls = OVSSwitch,dpid="0000000000000003")

r1 = net.addSwitch('r1',cls=OVSSwitch,dpid="0000000000000004")
r2 = net.addSwitch('r2',cls=OVSSwitch,dpid="0000000000000005")
r3 = net.addSwitch('r3',cls=OVSSwitch,dpid="0000000000000006")

http1 = net.addHost('http1', ip = '10.0.0.2/24', mac='00:00:00:00:00:02', defaultRoute = 'via 10.0.0.1')

h1 = net.addHost('h11', ip = '10.0.0.3/24', mac="00:00:00:00:00:03", defaultRoute = 'via 10.0.0.1')
h2 = net.addHost('h12', ip = '10.0.0.4/24', mac="00:00:00:00:00:04", defaultRoute = 'via 10.0.0.1')
h3 = net.addHost('h21', ip = '10.0.3.2/24', mac="00:00:00:00:03:02", defaultRoute = 'via 10.0.3.1')
h4 = net.addHost('h22', ip = '10.0.3.3/24', mac="00:00:00:00:03:03", defaultRoute = 'via 10.0.3.1')
h5 = net.addHost('h23', ip = '10.0.3.4/24', mac="00:00:00:00:03:04", defaultRoute = 'via 10.0.3.1')
h6 = net.addHost('h31', ip = '10.0.5.2/24', mac="00:00:00:00:05:02", defaultRoute = 'via 10.0.5.1')
h7 = net.addHost('h32', ip = '10.0.5.3/24', mac="00:00:00:00:05:03", defaultRoute = 'via 10.0.5.1')
h8 = net.addHost('h33', ip = '10.0.5.4/24', mac="00:00:00:00:05:04", defaultRoute = 'via 10.0.5.1')

net.addLink(r1,r2)
net.addLink(r1,r3,delay='5ms')
net.addLink(r2,r3)

net.addLink(s1,r1)
net.addLink(s2,r2)
net.addLink(s3,r3)

net.addLink(http1,s1)
net.addLink(h1,s1)
net.addLink(h2,s1)

net.addLink(h3,s2)
net.addLink(h4,s2)
net.addLink(h5,s2)

net.addLink(h6,s3)
net.addLink(h7,s3)
net.addLink(h8,s3)

r1.setMAC('F6:C5:73:99:F4:F7','r1-eth1')
r1.setMAC('E2:FA:8A:1F:99:10','r1-eth2')
r1.setMAC('C6:43:79:7E:EA:6B','r1-eth3')

r2.setMAC('D2:B3:40:BC:D9:29','r2-eth1')
r2.setMAC('8B:F0:Fb:28:FD:AF','r2-eth2')
r2.setMAC('48:6F:7C:61:42:55','r2-eth3')

r3.setMAC('26:C5:A4:01:75:26','r3-eth1')
r3.setMAC('93:3F:8A:E0:EE:6E','r3-eth2')
r3.setMAC('14:BA:BA:B6:4F:E1','r3-eth3')

net.build()

c1.start()
c2.start()

s1.start([c1])
s2.start([c1])
s3.start([c1])
r1.start([c2])
r2.start([c2])
r3.start([c2])

CLI(net)

net.stop()