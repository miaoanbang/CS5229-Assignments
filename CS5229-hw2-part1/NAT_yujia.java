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
import java.util.concurrent.ConcurrentHashMap;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.python.modules._hashlib;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * NAME: Chen Yujia Matric No.: A0091766U
 */
public class NAT implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;

    HashMap<String, String> RouterInterfaceMacMap = new HashMap<>();
    HashMap<Integer, String> IPTransMap = new HashMap<>();
    HashMap<String, OFPort> IPPortMap = new HashMap<>();
    HashMap<String, String> IPMacMap = new HashMap<>();
    HashMap<String, String> IPIPMap = new HashMap<>();
    ConcurrentHashMap<Integer, String> QueryIDSourceIPMap = new ConcurrentHashMap<>();
    ConcurrentHashMap<Integer, Long> QueryIDTimeoutMap = new ConcurrentHashMap<>();

    public static final long QUERY_ID_TIMEOUT_MILLIS = 60 * 1000;

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
            // handle ARPi for VIP
            if (pkt instanceof ARP) {
                ARP arpRequest = (ARP) eth.getPayload();
                IPv4Address targetProtocolAddress = arpRequest.getTargetProtocolAddress();

                if (RouterInterfaceMacMap.containsKey(targetProtocolAddress.toString())) {
                    String mac = RouterInterfaceMacMap.get(targetProtocolAddress.toString());
                    proxyArpReply(sw, pi, cntx, mac);
                    return Command.STOP;
                }
            }
        } else {
            if (pkt instanceof IPv4) {
                IPv4 ip_pkt = (IPv4) pkt;

                // currently only NAT ICMP packets - no-op for other traffic
                if (ip_pkt.getPayload() instanceof ICMP) {
                    ICMP icmp_payload = (ICMP) ip_pkt.getPayload();
                    byte[] icmp_bytes = icmp_payload.serialize();
                    int query_id = (icmp_bytes[4] & 0xFF) << 8 | (icmp_bytes[5] & 0xFF);
                    byte icmp_type = icmp_payload.getIcmpType();
                    if (QueryIDTimeoutMap.containsKey(query_id)) {
                        QueryIDTimeoutMap.put(query_id, System.currentTimeMillis());
                        if (icmp_type == ICMP.ECHO_REQUEST) {
                            proxyIcmpRequest(sw, pi, cntx);
                        } else if (icmp_type == ICMP.ECHO_REPLY) {
                            proxyIcmpReply(sw, pi, cntx, QueryIDSourceIPMap.get(query_id));
                        }
                        return Command.STOP;
                    } else if (icmp_type == ICMP.ECHO_REQUEST) {
                        String destIpAddress = ip_pkt.getDestinationAddress().toString();
                        if (IPPortMap.containsKey(destIpAddress) && IPMacMap.containsKey(destIpAddress)
                                && IPIPMap.containsKey(destIpAddress)) {
                            QueryIDSourceIPMap.put(query_id, ip_pkt.getSourceAddress().toString());
                            QueryIDTimeoutMap.put(query_id, System.currentTimeMillis());
                            proxyIcmpRequest(sw, pi, cntx);
                            return Command.STOP;
                        }
                    }
                }
            }
        }

        return Command.CONTINUE;
    }

    /**
     * used to send proxy Arp reply
     *
     * @param IOFSwitch         sw
     * @param OFPacketIn        pi
     * @param FloodlightContext cntx
     * @param String            mac
     */
    protected void proxyArpReply(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, String mac) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        if (!(eth.getPayload() instanceof ARP))
            return;
        ARP arpRequest = (ARP) eth.getPayload();

        // generate proxy ARP reply
        IPacket arpReply = new Ethernet().setSourceMACAddress(MacAddress.of(mac))
                .setDestinationMACAddress(eth.getSourceMACAddress()).setEtherType(EthType.ARP)
                .setVlanID(eth.getVlanID()).setPriorityCode(eth.getPriorityCode())
                .setPayload(new ARP().setHardwareType(ARP.HW_TYPE_ETHERNET).setProtocolType(ARP.PROTO_TYPE_IP)
                        .setHardwareAddressLength((byte) 6).setProtocolAddressLength((byte) 4).setOpCode(ARP.OP_REPLY)
                        .setSenderHardwareAddress(MacAddress.of(mac))
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
     * used to send proxy Icmp request
     *
     * @param IOFSwitch         sw
     * @param OFPacketIn        pi
     * @param FloodlightContext cntx
     */
    protected void proxyIcmpRequest(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        if (!(eth.getPayload() instanceof IPv4))
            return;
        IPv4 ip_pkt = (IPv4) eth.getPayload();

        String destIpAddress = ip_pkt.getDestinationAddress().toString();
        String modifiedSourceIpAddress = IPIPMap.get(destIpAddress);

        // modify source IP
        ip_pkt.setSourceAddress(modifiedSourceIpAddress);
        ip_pkt.resetChecksum();

        // generate proxy ICMP request
        IPacket icmpRequest = new Ethernet()
                .setSourceMACAddress(MacAddress.of(RouterInterfaceMacMap.get(modifiedSourceIpAddress)))
                .setDestinationMACAddress(MacAddress.of(IPMacMap.get(destIpAddress))).setEtherType(EthType.IPv4)
                .setVlanID(eth.getVlanID()).setPriorityCode(eth.getPriorityCode()).setPayload(ip_pkt);

        // push ICMP request out
        pushPacket(icmpRequest, sw, OFBufferId.NO_BUFFER, OFPort.ANY, IPPortMap.get(destIpAddress), cntx, true);

        return;
    }

    /**
     * used to send proxy Icmp reply
     *
     * @param IOFSwitch         sw
     * @param OFPacketIn        pi
     * @param FloodlightContext cntx
     * @param String            destIpAddress
     */
    protected void proxyIcmpReply(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, String destIpAddress) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        if (!(eth.getPayload() instanceof IPv4))
            return;
        IPv4 ip_pkt = (IPv4) eth.getPayload();

        // modify destination IP
        ip_pkt.setDestinationAddress(destIpAddress);
        ip_pkt.resetChecksum();

        // generate proxy ICMP reply
        IPacket icmpReply = new Ethernet().setSourceMACAddress(eth.getSourceMACAddress())
                .setDestinationMACAddress(MacAddress.of(IPMacMap.get(destIpAddress))).setEtherType(EthType.IPv4)
                .setVlanID(eth.getVlanID()).setPriorityCode(eth.getPriorityCode()).setPayload(ip_pkt);

        // push ICMP reply out
        pushPacket(icmpReply, sw, OFBufferId.NO_BUFFER, OFPort.ANY, IPPortMap.get(destIpAddress), cntx, true);

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
        IPIPMap.put("192.168.0.10", "192.168.0.1");
        IPIPMap.put("192.168.0.20", "192.168.0.2");
        IPIPMap.put("10.0.0.11", "10.0.0.1");
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        Thread t = new TimeoutChecker();
        t.start();
    }

    class TimeoutChecker extends Thread {
        @Override
        public void run() {
            while (true) {
                long currentTimeMillis = System.currentTimeMillis();
                for (Map.Entry<Integer, Long> entry : QueryIDTimeoutMap.entrySet()) {
                    if ((currentTimeMillis - entry.getValue()) > QUERY_ID_TIMEOUT_MILLIS) {
                        if (QueryIDTimeoutMap.remove(entry.getKey(), entry.getValue())) {
                            QueryIDSourceIPMap.remove(entry.getKey());
                            logger.info("Removed Query ID {}", entry.getKey());
                        }
                    }
                }
                try {
                    Thread.sleep(QUERY_ID_TIMEOUT_MILLIS);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
