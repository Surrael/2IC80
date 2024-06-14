package io.github.danielthedev.gwidt;

import org.pcap4j.packet.*;

public class NetworkExecutor {

    private static NetworkExecutor INSTANCE;

    public NetworkInterface<QuadPacket<EthernetPacket, IpV4Packet, TransportPacket, DnsPacket>> DNS_INTERFACE;
    public NetworkInterface<BiPacket<EthernetPacket, ArpPacket>> ARP_INTERFACE;

    /**
     * Constructor
     *
     * @param victimIp       IP address of the victim
     * @param defaultGateway IP address of the default gateway
     */
    private NetworkExecutor(String victimIp, String defaultGateway) {
        try {
            this.DNS_INTERFACE = new NetworkInterface<>("DNS", "udp port 53", packet -> {
                EthernetPacket ethernetPacket = (EthernetPacket) packet;
                if (ethernetPacket.getPayload() instanceof IpV6Packet) return null;
                IpV4Packet ipPacket = (IpV4Packet) ethernetPacket.getPayload();
                TransportPacket transportPacket = (TransportPacket) ipPacket.getPayload();
                DnsPacket dnsPacket = (DnsPacket) transportPacket.getPayload();
                return new QuadPacket<>(ethernetPacket, ipPacket, transportPacket, dnsPacket);
            });

            this.ARP_INTERFACE = new NetworkInterface<>("ARP", "(src host %s or src host %s) and arp".formatted(victimIp, defaultGateway), packet -> {
                EthernetPacket ethernetPacket = (EthernetPacket) packet;
                ArpPacket arpPacket = (ArpPacket) ethernetPacket.getPayload();
                return new BiPacket<>(ethernetPacket, arpPacket);
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Initialize the instance
     *
     * @param victimIp       victim IP
     * @param defaultGateway gateway IP
     */
    public static void initInstance(String victimIp, String defaultGateway) {
        INSTANCE = new NetworkExecutor(victimIp, defaultGateway);
    }

    /**
     * Get the instance
     *
     * @return instance
     */
    public static NetworkExecutor getInstance() {
        return INSTANCE;
    }

    /**
     * Data structure containing two packets
     */
    public static class BiPacket<A extends Packet, B extends Packet> {
        private final A a;
        private final B b;


        BiPacket(A a, B b) {
            this.a = a;
            this.b = b;
        }

        public A getA() {
            return a;
        }

        public B getB() {
            return b;
        }
    }

    /**
     * Data structure containing three packets
     */
    public static class TriPacket<A extends Packet, B extends Packet, C extends Packet> extends BiPacket<A, B> {

        private final C c;

        TriPacket(A a, B b, C c) {
            super(a, b);
            this.c = c;
        }

        public C getC() {
            return c;
        }
    }

    /**
     * Data structure containing four packets
     */
    public static class QuadPacket<A extends Packet, B extends Packet, C extends Packet, D extends Packet> extends TriPacket<A, B, C> {

        private final D d;


        QuadPacket(A a, B b, C c, D d) {
            super(a, b, c);
            this.d = d;
        }

        public D getD() {
            return d;
        }
    }


}
