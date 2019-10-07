#!/usr/bin/python

"""
Topology with 3 switches interconnected.
Pravein, Aug 2017
"""

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
import subprocess

client1InfIP = '192.168.0.1/24'
client2InfIP = '192.168.0.2/24'
serverInfIP = '10.0.0.1/24'

def setupHostRoutes(host):
    print 'Setting host commands for %s' % host.name
    if(host.name == 'client1'):
        defaultgw = client1InfIP.split('/')[0]
        host.cmd('route del -net 192.0.0.0/8 dev %s-eth0' % host.name)
    elif(host.name == 'client2'):
        defaultgw = client2InfIP.split('/')[0]
        host.cmd('route del -net 192.0.0.0/8 dev %s-eth0' % host.name)
    elif(host.name == 'server'):
        defaultgw = serverInfIP.split('/')[0]
        host.cmd('route del -net 10.0.0.0/8 dev %s-eth0' % host.name)
    print host.name, defaultgw
    host.cmd('sudo route add %s/32 dev %s-eth0' % (defaultgw, host.name))
    print 'route add %s/32 dev %s-eth0' % (defaultgw, host.name)
    host.cmd('sudo route add default gw %s dev %s-eth0' % (defaultgw, host.name))


def NatTask():

    net = Mininet( controller=Controller, switch=OVSSwitch)

    print "*** Creating controllers. Make sure you run the controller at port 6633!!"
    ctrl = RemoteController( 'ctrl', ip='127.0.0.1',port=6633)

    print "*** Creating switches"
    gateway = net.addSwitch( 'S1' )

    print "*** Creating hosts"
    client1 = net.addHost('client1', ip='192.168.0.10/24', mac='00:00:00:00:00:01');
    client2 = net.addHost('client2', ip='192.168.0.20/24', mac='00:00:00:00:00:02');
    server = net.addHost('server', ip='10.0.0.11/24',   mac='00:00:00:00:00:03');


    print "*** Creating links"

    net.addLink(client1, gateway)
    net.addLink(client2, gateway)
    net.addLink(gateway, server)

    client1intf = client1.defaultIntf()
    client2intf = client2.defaultIntf()
    serverintf = server.defaultIntf()

    client1intf.setIP(client1InfIP)
    client2intf.setIP(client2InfIP)
    serverintf.setIP(serverInfIP)
    for host in client1, client2, server:
        setupHostRoutes(host)
    print "*** Starting network"
    net.build()
    gateway.start( [ ctrl ] )


    print "*** Running CLI"
    CLI( net )

    print "*** Stopping network"
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )  # for CLI output
    NatTask()
