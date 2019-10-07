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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.python.modules._hashlib;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by pravein on 28/9/17.
 * 
 * @Author <Name/Matricno> Miao Anbang / A0091818X
 * 
 *         Date : 6 Oct 2019
 */
public class NAT implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;

    HashMap<String, String> RouterInterfaceMacMap = new HashMap<>();
    HashMap<Integer, String> IPTransMap = new HashMap<>();
    HashMap<String, OFPort> IPPortMap = new HashMap<>();
    HashMap<String, String> IPMacMap = new HashMap<>();
    HashMap<String, String> IPRouterIPMap = new HashMap<>();
    ConcurrentHashMap<Integer, String> queryIDToSourceIPMap = new ConcurrentHashMap<>();
    ConcurrentHashMap<Integer, Long> queryIDToTimeoutMap = new ConcurrentHashMap<>();

    // timeout after 1 minute
    private static final long QUERY_ID_TIMEOUT_MILLISECOND = 60 * 1000;

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

                if (RouterInterfaceMacMap.containsKey(targetProtocolAddress.toString())) {
                    String macAddress = RouterInterfaceMacMap.get(targetProtocolAddress.toString());
                    proxyArpReply(sw, pi, cntx, macAddress);
                    return Command.STOP;
                }
            }
        } else {
            // currently only load balance IPv4 packets - no-op for other traffic
            if (pkt instanceof IPv4) {
                IPv4 ip_pkt = (IPv4) pkt;

                // only for ICMP packets
                if (ip_pkt.getPayload() instanceof ICMP) {
                    ICMP icmp_payload = (ICMP) ip_pkt.getPayload();
                    // get icmp type
                    byte icmp_type = icmp_payload.getIcmpType();
                    // get icmp payload
                    byte[] icmp_payload_bytes = icmp_payload.serialize();
                    // get icmp identifier as query id
                    // icmp identifier are at byte 4-5 of the payload
                    Integer query_id = (icmp_payload_bytes[4] & 0xFF) << 8 | (icmp_payload_bytes[5] & 0xFF);

                    // handle icmp request/reply if query id is in queryIDToTimeoutMap
                    if (queryIDToTimeoutMap.containsKey(query_id)) {
                        queryIDToTimeoutMap.put(query_id, System.currentTimeMillis());
                        if (icmp_type == ICMP.ECHO_REQUEST) {
                            processIcmpRequest(sw, pi, cntx);
                        } else if (icmp_type == ICMP.ECHO_REPLY) {
                            processIcmpReply(sw, pi, cntx, queryIDToSourceIPMap.get(query_id));
                        }
                        return Command.STOP;
                        // handle icmp request if query id is not in queryIDToTimeoutMap
                    } else if (icmp_type == ICMP.ECHO_REQUEST) {
                        String destinationIpAddress = ip_pkt.getDestinationAddress().toString();
                        if (IPPortMap.containsKey(destinationIpAddress) && IPMacMap.containsKey(destinationIpAddress)
                                && IPRouterIPMap.containsKey(destinationIpAddress)) {
                            queryIDToSourceIPMap.put(query_id, ip_pkt.getSourceAddress().toString());
                            queryIDToTimeoutMap.put(query_id, System.currentTimeMillis());
                            processIcmpRequest(sw, pi, cntx);
                            return Command.STOP;
                        }
                        // do nothing if timeout
                    } else {
                        return Command.STOP;
                    }
                }
            }
        }
        return Command.CONTINUE;
    }

    /**
     * proxy Arp reply
     * 
     * @param IOFSwitch         sw
     * @param OFPacketIn        pi
     * @param FloodlightContext cntx
     * @param String            macAddress
     */
    void proxyArpReply(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, String macAddress) {
        logger.debug("ProxyArpReply");

        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        // retrieve original arp to determine host configured gw IP address
        if (!(eth.getPayload() instanceof ARP))
            return;
        ARP arpRequest = (ARP) eth.getPayload();

        // have to do proxy arp reply since at this point we cannot determine the
        // requesting application type

        // generate proxy ARP reply
        IPacket arpReply = new Ethernet().setSourceMACAddress(MacAddress.of(macAddress))
                .setDestinationMACAddress(eth.getSourceMACAddress()).setEtherType(EthType.ARP)
                .setVlanID(eth.getVlanID()).setPriorityCode(eth.getPriorityCode())
                .setPayload(new ARP().setHardwareType(ARP.HW_TYPE_ETHERNET).setProtocolType(ARP.PROTO_TYPE_IP)
                        .setHardwareAddressLength((byte) 6).setProtocolAddressLength((byte) 4).setOpCode(ARP.OP_REPLY)
                        .setSenderHardwareAddress(MacAddress.of(macAddress))
                        .setSenderProtocolAddress(arpRequest.getTargetProtocolAddress())
                        .setTargetHardwareAddress(eth.getSourceMACAddress())
                        .setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));

        // push ARP reply out
        pushPacket(arpReply, sw, OFBufferId.NO_BUFFER, OFPort.ANY,
                (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
                        : pi.getMatch().get(MatchField.IN_PORT)),
                cntx, true);

        return;
    }

    /**
     * process ICMP request packets
     * 
     * @param IOFSwitch         sw
     * @param OFPacketIn        pi
     * @param FloodlightContext cntx
     */
    void processIcmpRequest(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        if (!(eth.getPayload() instanceof IPv4))
            return;
        IPv4 ip_pkt = (IPv4) eth.getPayload();

        String destinationIpAddress = ip_pkt.getDestinationAddress().toString();
        String translatedSourceIpAddress = IPRouterIPMap.get(destinationIpAddress);

        // modify source IP address and reset checksum
        ip_pkt.setSourceAddress(translatedSourceIpAddress).resetChecksum();

        // generate proxy ICMP request
        IPacket icmpRequest = new Ethernet()
                .setSourceMACAddress(MacAddress.of(RouterInterfaceMacMap.get(translatedSourceIpAddress)))
                .setDestinationMACAddress(MacAddress.of(IPMacMap.get(destinationIpAddress))).setEtherType(EthType.IPv4)
                .setVlanID(eth.getVlanID()).setPriorityCode(eth.getPriorityCode()).setPayload(ip_pkt);

        // push ICMP request out
        pushPacket(icmpRequest, sw, OFBufferId.NO_BUFFER, OFPort.ANY, IPPortMap.get(destinationIpAddress), cntx, true);

        return;
    }

    /**
     * process ICMP reply packets
     * 
     * @param IOFSwitch         sw
     * @param OFPacketIn        pi
     * @param FloodlightContext cntx
     * @param String            destinationIpAddress
     */
    protected void processIcmpReply(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, String destinationIpAddress) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        if (!(eth.getPayload() instanceof IPv4))
            return;
        IPv4 ip_pkt = (IPv4) eth.getPayload();

        // modify destination IP address and reset checksum
        ip_pkt.setDestinationAddress(destinationIpAddress).resetChecksum();

        // generate proxy ICMP reply
        IPacket icmpReply = new Ethernet().setSourceMACAddress(eth.getSourceMACAddress())
                .setDestinationMACAddress(MacAddress.of(IPMacMap.get(destinationIpAddress))).setEtherType(EthType.IPv4)
                .setVlanID(eth.getVlanID()).setPriorityCode(eth.getPriorityCode()).setPayload(ip_pkt);

        // push ICMP reply packget out
        pushPacket(icmpReply, sw, OFBufferId.NO_BUFFER, OFPort.ANY, IPPortMap.get(destinationIpAddress), cntx, true);

        return;
    }

    /**
     * used to push any packet - borrowed routine from Forwarding
     * 
     * @param OFPacketIn        pi
     * @param IOFSwitch         sw
     * @param int               bufferId
     * @param short             inPort
     * @param short             outPort
     * @param FloodlightContext cntx
     * @param boolean           flush
     */
    public void pushPacket(IPacket packet, IOFSwitch sw, OFBufferId bufferId, OFPort inPort, OFPort outPort,
            FloodlightContext cntx, boolean flush) {
        if (logger.isTraceEnabled()) {
            logger.trace("PacketOut srcSwitch={} inPort={} outPort={}", new Object[] { sw, inPort, outPort });
        }

        OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();

        // set actions
        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(sw.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(Integer.MAX_VALUE).build());

        pob.setActions(actions);

        // set buffer_id, in_port
        pob.setBufferId(bufferId);
        pob.setInPort(inPort);

        // set data - only if buffer_id == -1
        if (pob.getBufferId() == OFBufferId.NO_BUFFER) {
            if (packet == null) {
                logger.error("BufferId is not set and packet data is null. " + "Cannot send packetOut. "
                        + "srcSwitch={} inPort={} outPort={}", new Object[] { sw, inPort, outPort });
                return;
            }
            byte[] packetData = packet.serialize();
            pob.setData(packetData);
        }
        sw.write(pob.build());
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

        // Client/Server IP to Router IP mappings
        IPRouterIPMap.put("192.168.0.10", "192.168.0.1");
        IPRouterIPMap.put("192.168.0.20", "192.168.0.2");
        IPRouterIPMap.put("10.0.0.11", "10.0.0.1");
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

        // execute task every 5 seconds to clear query id for timeout query id sesstions
        Runnable task = new Runnable() {
            public void run() {
                long currentTimeMillisecond = System.currentTimeMillis();
                for (Map.Entry<Integer, Long> entry : queryIDToTimeoutMap.entrySet()) {
                    if ((currentTimeMillisecond - entry.getValue()) > QUERY_ID_TIMEOUT_MILLISECOND) {
                        queryIDToTimeoutMap.remove(entry.getKey());
                        queryIDToSourceIPMap.remove(entry.getKey());
                        logger.info("Removed Query ID {}", entry.getKey());
                    }
                }
            }
        };
        ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(1);
        scheduledExecutorService.scheduleAtFixedRate(task, 5, 5, TimeUnit.SECONDS);
    }
}
