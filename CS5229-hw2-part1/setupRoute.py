#!/usr/bin/python

import sys
import os
client1InfIP = '192.168.0.1/24'
client2InfIP = '192.168.0.2/24'
serverInfIP = '10.0.0.1/24'

def setupHostRoutes(host):
    print 'Setting host commands for %s' % host
    if(host == 'client1'):
        defaultgw = client1InfIP.split('/')[0]
        os.system('route del -net 192.168.0.0/24')
    elif(host == 'client2'):
        defaultgw = client2InfIP.split('/')[0]
        os.system('route del -net 192.168.0.0/24' )
    elif(host == 'server'):
        defaultgw = serverInfIP.split('/')[0]
        os.system('route del -net 10.0.0.0/24' )
    print host, defaultgw
    os.system('sudo route add %s/32 dev %s-eth0' % (defaultgw, host))
    print 'route add %s/32 dev %s-eth0' % (defaultgw, host)
    os.system('sudo route add default gw %s dev %s-eth0' % (defaultgw, host))

setupHostRoutes(sys.argv[1])
