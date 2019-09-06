#!/usr/bin/python

"""
@Author <Name/Matricno> Miao Anbang / A0091818X
Date : 4 Sep 2019
"""


import httplib
import json


class flowStat(object):
    def __init__(self, server):
        self.server = server

    def get(self, switch):
        ret = self.rest_call({}, 'GET', switch)
        return json.loads(ret[2])

    def rest_call(self, data, action, switch):
        path = '/wm/core/switch/'+switch+"/flow/json"
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
        }
        body = json.dumps(data)
        conn = httplib.HTTPConnection(self.server, 8080)
        #print path
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        conn.close()
        return ret


class StaticFlowPusher(object):
    def __init__(self, server):
        self.server = server

    def get(self, data):
        ret = self.rest_call({}, 'GET')
        return json.loads(ret[2])

    def set(self, data):
        ret = self.rest_call(data, 'POST')
        return ret[0] == 200

    def remove(self, objtype, data):
        ret = self.rest_call(data, 'DELETE')
        return ret[0] == 200

    def rest_call(self, data, action):
        path = '/wm/staticflowpusher/json'
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
        }
        body = json.dumps(data)
        conn = httplib.HTTPConnection(self.server, 8080)
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        #print ret
        conn.close()
        return ret


pusher = StaticFlowPusher('127.0.0.1')
flowget = flowStat('127.0.0.1')

# To insert the policies for the traffic applicable to path between S1 and S2


def S1toS2():
    # utilize mininet_add_queue.py queue 1
    S1_Limit_Policy = {
        "switch": "00:00:00:00:00:00:00:01",
        "name": "S1_Limit_Policy",
        "cookie": "0",
        "priority": "2",
        "in_port": "1",
        "eth_type": "0x800",
        "ipv4_src": "10.0.0.1",
        "ipv4_dst": "10.0.0.2",
        "active": "true",
        "actions": "set_queue=1,output=2"
    }
    pusher.set(S1_Limit_Policy)

# To insert the policies for the traffic applicable to path between S2 and S3


def S2toS3():
    # use a for loop to specify and push the udp port between 1000 and 1100
    for port in range(1000, 1101):
        S2_UDP_Policy = {
            "switch": "00:00:00:00:00:00:00:02",
            "name": "S2_UDP_Policy—_" + str(port),
            "cookie": "0",
            "priority": "2",
            "in_port": "1",
            "eth_type": "0x800",
            "ipv4_src": "10.0.0.2",
            "ipv4_dst": "10.0.0.3",
            "ip_proto": "0x11",
            "udp_dst": str(port),
            "active": "true"
        }

        S3_UDP_Policy = {
            "switch": "00:00:00:00:00:00:00:03",
            "name": "S3_UDP_Policy—_" + str(port),
            "cookie": "0",
            "priority": "2",
            "in_port": "1",
            "eth_type": "0x800",
            "ipv4_src": "10.0.0.3",
            "ipv4_dst": "10.0.0.2",
            "ip_proto": "0x11",
            "udp_dst": str(port),
            "active": "true"
        }

        pusher.set(S2_UDP_Policy)
        pusher.set(S3_UDP_Policy)

# To insert the policies for the traffic applicable to path between S1 and S3


def S1toS3():
    # 1Mbps_Policy
    S1_1Mbps_Policy = {
        "switch": "00:00:00:00:00:00:00:01",
        "name": "S1_1Mbps_Policy",
        "cookie": "0",
        "priority": "2",
        "in_port": "1",
        "eth_type": "0x800",
        "ipv4_src": "10.0.0.1",
        "ipv4_dst": "10.0.0.3",
        "ip_proto": "0x06",
        "tcp_dst": "80",
        "active": "true",
        "actions": "set_queue=1,output=3"
    }

    # 512Kbps_Policy
    S1_512Kbps_Policy = {
        "switch": "00:00:00:00:00:00:00:01",
        "name": "S1_512Kbps_Policy",
        "cookie": "0",
        "priority": "2",
        "in_port": "1",
        "eth_type": "0x800",
        "ipv4_src": "10.0.0.1",
        "ipv4_dst": "10.0.0.3",
        "ip_proto": "0x06",
        "tcp_dst": "80",
        "active": "true",
        "actions": "set_queue=2,output=3"
    }

    byteCount = 0
    while (True):
        # Rate Limit Traffic to 1Mbps for 20Mb transfer;
        pusher.set(S1_1Mbps_Policy)
        prev_byteCount = byteCount
        while (byteCount - prev_byteCount) * 8 < 20000000:
            ret = flowget.get("00:00:00:00:00:00:00:01")
            for flow in ret['flows']:
                if flow['priority'] == '2' and 'tcp_dst' in flow['match']:
                    byteCount = int(flow['byteCount'])
                    break
        # Rate Limit to 512Kbps next 10Mb transfer;
        pusher.set(S1_512Kbps_Policy)
        prev_byteCount = byteCount
        while (byteCount - prev_byteCount) * 8 < 10000000:
            ret = flowget.get("00:00:00:00:00:00:00:01")
            for flow in ret['flows']:
                if flow['priority'] == '2' and 'tcp_dst' in flow['match']:
                    byteCount = int(flow['byteCount'])
                    break


def staticForwarding():
    # Below 4 flows are for setting up the static forwarding for the path H1->S1->S2->H2 & vice-versa
    # Define static flow for Switch S1 for packet forwarding b/w h1 and h2
    S1Staticflow1 = {'switch': "00:00:00:00:00:00:00:01", "name": "S1h1toh2", "cookie": "0",
                     "priority": "1", "in_port": "1", "eth_type": "0x800", "ipv4_src": "10.0.0.1",
                     "ipv4_dst": "10.0.0.2", "active": "true", "actions": "output=2"}
    S1Staticflow2 = {'switch': "00:00:00:00:00:00:00:01", "name": "S1h2toh1", "cookie": "0",
                     "priority": "1", "in_port": "2", "eth_type": "0x800", "ipv4_src": "10.0.0.2",
                     "ipv4_dst": "10.0.0.1", "active": "true", "actions": "output=1"}
    # Define static flow for Switch S2 for packet forwarding b/w h1 and h2
    S2Staticflow1 = {'switch': "00:00:00:00:00:00:00:02", "name": "S2h2toh1", "cookie": "0",
                     "priority": "1", "in_port": "1", "eth_type": "0x800", "ipv4_src": "10.0.0.2",
                     "ipv4_dst": "10.0.0.1", "active": "true", "actions": "output=2"}
    S2Staticflow2 = {'switch': "00:00:00:00:00:00:00:02", "name": "S2h1toh2", "cookie": "0",
                     "priority": "1", "in_port": "2", "eth_type": "0x800", "ipv4_src": "10.0.0.1",
                     "ipv4_dst": "10.0.0.2", "active": "true", "actions": "output=1"}

    # Below 4 flows are for setting up the static forwarding for the path H1->S1->S3->H3 & vice-versa
    # Define static flow for Switch S1 for packet forwarding b/w h1 and h3
    S1Staticflow3 = {'switch': "00:00:00:00:00:00:00:01", "name": "S1h1toh3", "cookie": "0",
                     "priority": "1", "in_port": "1", "eth_type": "0x800", "ipv4_src": "10.0.0.1",
                     "ipv4_dst": "10.0.0.3", "active": "true", "actions": "output=3"}
    S1Staticflow4 = {'switch': "00:00:00:00:00:00:00:01", "name": "S1h3toh1", "cookie": "0",
                     "priority": "1", "in_port": "3", "eth_type": "0x800", "ipv4_src": "10.0.0.3",
                     "ipv4_dst": "10.0.0.1", "active": "true", "actions": "output=1"}
    # Define static flow for Switch S3 for packet forwarding b/w h1 and h3
    S3Staticflow1 = {'switch': "00:00:00:00:00:00:00:03", "name": "S3h3toh1", "cookie": "0",
                     "priority": "1", "in_port": "1", "eth_type": "0x800", "ipv4_src": "10.0.0.3",
                     "ipv4_dst": "10.0.0.1", "active": "true", "actions": "output=2"}
    S3Staticflow2 = {'switch': "00:00:00:00:00:00:00:03", "name": "S3h1toh3", "cookie": "0",
                     "priority": "1", "in_port": "2", "eth_type": "0x800", "ipv4_src": "10.0.0.1",
                     "ipv4_dst": "10.0.0.3", "active": "true", "actions": "output=1"}

    # Below 4 flows are for setting up the static forwarding for the path H2->S2->S3->H3 & vice-versa
    # Define static flow for Switch S1 for packet forwarding b/w h2 and h3
    S2Staticflow3 = {'switch': "00:00:00:00:00:00:00:02", "name": "S2h2toh3", "cookie": "0",
                     "priority": "1", "in_port": "1", "eth_type": "0x800", "ipv4_src": "10.0.0.2",
                     "ipv4_dst": "10.0.0.3", "active": "true", "actions": "output=3"}
    S2Staticflow4 = {'switch': "00:00:00:00:00:00:00:02", "name": "S2h3toh2", "cookie": "0",
                     "priority": "1", "in_port": "3", "eth_type": "0x800", "ipv4_src": "10.0.0.3",
                     "ipv4_dst": "10.0.0.2", "active": "true", "actions": "output=1"}
    # Define static flow for Switch S3 for packet forwarding b/w h2 and h3
    S3Staticflow3 = {'switch': "00:00:00:00:00:00:00:03", "name": "S3h3toh2", "cookie": "0",
                     "priority": "1", "in_port": "1", "eth_type": "0x800", "ipv4_src": "10.0.0.3",
                     "ipv4_dst": "10.0.0.2", "active": "true", "actions": "output=3"}
    S3Staticflow4 = {'switch': "00:00:00:00:00:00:00:03", "name": "S3h2toh3", "cookie": "0",
                     "priority": "1", "in_port": "2", "eth_type": "0x800", "ipv4_src": "10.0.0.2",
                     "ipv4_dst": "10.0.0.3", "active": "true", "actions": "output=1"}

    # Now, Insert the flows to the switches
    pusher.set(S1Staticflow1)
    pusher.set(S1Staticflow2)
    pusher.set(S1Staticflow3)
    pusher.set(S1Staticflow4)

    pusher.set(S2Staticflow1)
    pusher.set(S2Staticflow2)
    pusher.set(S2Staticflow3)
    pusher.set(S2Staticflow4)

    pusher.set(S3Staticflow1)
    pusher.set(S3Staticflow2)
    pusher.set(S3Staticflow3)
    pusher.set(S3Staticflow4)


if __name__ == '__main__':
    staticForwarding()
    S1toS2()
    S2toS3()
    S1toS3()
    pass
