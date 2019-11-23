#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import OVSController
from mininet.cli import CLI
import os

myBandwidth = 100
myDelay = '5ms'
myQueueSize = 1000
myLossPercentage = 1

class BellTopo( Topo ):
    "Single switch connected to n hosts."
    def build( self, n=8 ):
	    switch1 = self.addSwitch( 's1' )
	    switch2 = self.addSwitch( 's2' )
	    # Setting the bottleneck link parameters (htb -> Hierarchical token bucket rate limiting)
	    self.addLink( switch1, switch2, bw=myBandwidth, delay=myDelay, loss=myLossPercentage, max_queue_size=myQueueSize, use_htb=True )
	    for h in range(n):
	        # Each host gets 50%/n of system CPU
	        host = self.addHost( 'h%s' % (h + 1) )
	        if h < 4:
		        self.addLink(host, switch1)
	        else:
			    self.addLink(host, switch2)
			

def perfTest():
    "Create network and run simple performance test"
    topo = BellTopo( n=8 )
    net = Mininet( topo=topo,
	           host=CPULimitedHost, link=TCLink, controller = OVSController)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections( net.hosts )
    # print "Testing network connectivity"
    # net.pingAll()
    #print "Testing bandwidth between h1 and h2"
    #h1, h2 = net.get( 'h1', 'h2' )
    #net.iperf( (h1, h2) )
    CLI( net )
    net.stop()

if __name__ == '__main__':
    os.system("killall /usr/bin/ovs-testcontroller")
    setLogLevel( 'info' )
    perfTest()
