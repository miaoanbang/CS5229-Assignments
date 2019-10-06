package net.floodlightcontroller.natcs5229;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IListener;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.util.FlowModUtils;
import org.kohsuke.args4j.CmdLineException;
import org.projectfloodlight.openflow.protocol.*;
import java.io.IOException;
import java.util.*;
import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.concurrent.ConcurrentSkipListSet;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.python.modules._hashlib;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;

/**
 * Created by pravein on 28/9/17.
 * 
 * @Author <Name/Matricno> Miao Anbang / A0091818X 
 * 
 * Date : 6 Oct 2019
 */
public class NAT implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;

    HashMap<String, String> RouterInterfaceMacMap = new HashMap<>();
    HashMap<Integer, String> IPTransMap = new HashMap<>();
    HashMap<String, OFPort> IPPortMap = new HashMap<>();
    HashMap<String, String> IPMacMap = new HashMap<>();

    protected HashMap<String, LBVip> vips;
	protected HashMap<String, LBPool> pools;
    protected HashMap<Integer, String> vipIpToId;
    
    @Override
    public String getName() {
        return NAT.class.getName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }

    // Main Place to Handle PacketIN to perform NAT
    private Command handlePacketIn(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        IPacket pkt = eth.getPayload();

        if (eth.isBroadcast() || eth.isMulticast()) {
            // handle ARP for VIP
            if (pkt instanceof ARP) {
                // retrieve arp to determine target IP address
                ARP arpRequest = (ARP) pkt;

                IPv4Address targetProtocolAddress = arpRequest.getTargetProtocolAddress();

                if (vipIpToId.containsKey(targetProtocolAddress.getInt())) {
                    String vipId = vipIpToId.get(targetProtocolAddress.getInt());
                    vipProxyArpReply(sw, pi, cntx, vipId);
                    return Command.STOP;
                }
            }
        } else {
            // currently only load balance IPv4 packets - no-op for other traffic
            if (pkt instanceof IPv4) {
                IPv4 ip_pkt = (IPv4) pkt;

                // If match Vip and port, check pool and choose member
                int destIpAddress = ip_pkt.getDestinationAddress().getInt();

                if (vipIpToId.containsKey(destIpAddress)) {
                    IPClient client = new IPClient();
                    client.ipAddress = ip_pkt.getSourceAddress();
                    client.nw_proto = ip_pkt.getProtocol();
                    if (ip_pkt.getPayload() instanceof TCP) {
                        TCP tcp_pkt = (TCP) ip_pkt.getPayload();
                        client.srcPort = tcp_pkt.getSourcePort();
                        client.targetPort = tcp_pkt.getDestinationPort();
                    }
                    if (ip_pkt.getPayload() instanceof UDP) {
                        UDP udp_pkt = (UDP) ip_pkt.getPayload();
                        client.srcPort = udp_pkt.getSourcePort();
                        client.targetPort = udp_pkt.getDestinationPort();
                    }
                    if (ip_pkt.getPayload() instanceof ICMP) {
                        client.srcPort = TransportPort.of(8);
                        client.targetPort = TransportPort.of(0);
                    }

                    LBVip vip = vips.get(vipIpToId.get(destIpAddress));
                    if (vip == null) // fix dereference violations
                        return Command.CONTINUE;
                    LBPool pool = pools.get(vip.pickPool(client));
                    if (pool == null) // fix dereference violations
                        return Command.CONTINUE;
                    LBMember member = members.get(pool.pickMember(client));
                    if (member == null) // fix dereference violations
                        return Command.CONTINUE;

                    // for chosen member, check device manager and find and push routes, in both
                    // directions
                    pushBidirectionalVipRoutes(sw, pi, cntx, client, member);

                    // packet out based on table rule
                    pushPacket(pkt, sw, pi.getBufferId(),
                            (pi.getVersion().compareTo(OFVersion.OF_12) < 0) ? pi.getInPort()
                                    : pi.getMatch().get(MatchField.IN_PORT),
                            OFPort.TABLE, cntx, true);

                    return Command.STOP;
                }
            }
        }
        return Command.CONTINUE;
    }

    protected void vipProxyArpReply(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, String vipId) {
        log.debug("vipProxyArpReply");

        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        // retrieve original arp to determine host configured gw IP address
        if (!(eth.getPayload() instanceof ARP))
            return;
        ARP arpRequest = (ARP) eth.getPayload();

        // have to do proxy arp reply since at this point we cannot determine the
        // requesting application type

        // generate proxy ARP reply
        IPacket arpReply = new Ethernet().setSourceMACAddress(vips.get(vipId).proxyMac)
                .setDestinationMACAddress(eth.getSourceMACAddress()).setEtherType(EthType.ARP)
                .setVlanID(eth.getVlanID()).setPriorityCode(eth.getPriorityCode())
                .setPayload(new ARP().setHardwareType(ARP.HW_TYPE_ETHERNET).setProtocolType(ARP.PROTO_TYPE_IP)
                        .setHardwareAddressLength((byte) 6).setProtocolAddressLength((byte) 4).setOpCode(ARP.OP_REPLY)
                        .setSenderHardwareAddress(vips.get(vipId).proxyMac)
                        .setSenderProtocolAddress(arpRequest.getTargetProtocolAddress())
                        .setTargetHardwareAddress(eth.getSourceMACAddress())
                        .setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));

        // push ARP reply out
        pushPacket(arpReply, sw, OFBufferId.NO_BUFFER, OFPort.ANY,
                (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
                        : pi.getMatch().get(MatchField.IN_PORT)),
                cntx, true);
        log.debug("proxy ARP reply pushed as {}", IPv4.fromIPv4Address(vips.get(vipId).address));

        return;
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch (msg.getType()) {
        case PACKET_IN:
            return handlePacketIn(sw, (OFPacketIn) msg, cntx);
        default:
            break;
        }
        logger.warn("Received unexpected message {}", msg);
        return Command.CONTINUE;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = LoggerFactory.getLogger(NAT.class);

        // Use the below HashMaps as per your need

        // Router Interface IP to Mac address Mappings
        RouterInterfaceMacMap.put("10.0.0.1", "00:23:10:00:00:01");
        RouterInterfaceMacMap.put("192.168.0.1", "00:23:10:00:00:02");
        RouterInterfaceMacMap.put("192.168.0.2", "00:23:10:00:00:03");

        // IP to Router Interface mappings
        IPPortMap.put("192.168.0.10", OFPort.of(1));
        IPPortMap.put("192.168.0.20", OFPort.of(2));
        IPPortMap.put("10.0.0.11", OFPort.of(3));

        // Client/Server ip to Mac mappings
        IPMacMap.put("192.168.0.10", "00:00:00:00:00:01");
        IPMacMap.put("192.168.0.20", "00:00:00:00:00:02");
        IPMacMap.put("10.0.0.11", "00:00:00:00:00:03");
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
}
