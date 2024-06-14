package io.github.danielthedev.gwidt;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;


public class PacketFactory {
    //============================================ Methods for ARP ===================================================//

    /**
     * Create an ARP packet
     *
     * @param srcMac          Source MAC address
     * @param strSrcIp        Source IP address
     * @param strDstIpAddress Destination IP address
     * @param destMac         Destination MAC address
     * @param operation       ARP operation
     * @return ARP packet (Ethernet packet)
     */
    private static EthernetPacket createARPPacket(MacAddress srcMac, String strSrcIp, String strDstIpAddress, MacAddress destMac, ArpOperation operation) {
        if (operation == ArpOperation.REQUEST) destMac = MacAddress.ETHER_BROADCAST_ADDRESS;
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        try {
            arpBuilder
                    .hardwareType(ArpHardwareType.ETHERNET)
                    .protocolType(EtherType.IPV4)
                    .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                    .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                    .operation(operation)
                    .srcHardwareAddr(srcMac)
                    .srcProtocolAddr(InetAddress.getByName(strSrcIp))
                    .dstHardwareAddr(destMac)
                    .dstProtocolAddr(InetAddress.getByName(strDstIpAddress));
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder
                .dstAddr(destMac)
                .srcAddr(srcMac)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);
        return etherBuilder.build();
    }

    /**
     * Create an ARP reply packet
     *
     * @param srcMac          Source MAC address
     * @param strSrcIp        Source IP address
     * @param strDstIpAddress Destination IP address
     * @param dstMac          Destination MAC address
     * @return ARP reply packet (Ethernet packet)
     */
    public static EthernetPacket createARPReplyPacket(MacAddress srcMac, String strSrcIp, String strDstIpAddress, MacAddress dstMac) {
        return createARPPacket(srcMac, strSrcIp, strDstIpAddress, dstMac, ArpOperation.REPLY);
    }

    /**
     * Create an ARP request packet
     *
     * @param srcMac          Source MAC address
     * @param strSrcIp        Source IP address
     * @param strDstIpAddress Destination IP address
     * @return ARP request packet (Ethernet packet)
     */
    public static EthernetPacket createARPRequestPacket(MacAddress srcMac, String strSrcIp, String strDstIpAddress) {
        return createARPPacket(srcMac, strSrcIp, strDstIpAddress, null, ArpOperation.REQUEST);
    }

    //============================================ Methods for DNS ===================================================//

    /**
     * Create a list of DNS answer resource records
     *
     * @param dnsPacket DNS query packet
     * @param ipAddress IP address to be used in the answer records
     * @return List of DNS answer resource records
     */
    public static List<DnsResourceRecord> createDnsResourceRecord(DnsPacket dnsPacket, Inet4Address ipAddress) {
        DnsResourceRecord.Builder dnsResourceRecordBuilder = new DnsResourceRecord.Builder();
        DnsRDataA.Builder dataBuilder = new DnsRDataA.Builder();
        dataBuilder.address(ipAddress);
        DnsRDataA rData = dataBuilder.build();

        if (rData.length() >= Short.MAX_VALUE) {
            throw new IllegalArgumentException("Cannot create list of resource records: rData does not fit in RR");
        }

        dnsResourceRecordBuilder
                .name(dnsPacket.getHeader().getQuestions().get(0).getQName())
                .dataType(DnsResourceRecordType.A) // Type A for IPv4 address
                .dataClass(DnsClass.IN) // Internet class
                .ttl(100) // TTL in seconds
                .rData(rData)
                .rdLength((short) rData.length());

        ArrayList<DnsResourceRecord> result = new ArrayList<>();
        result.add(dnsResourceRecordBuilder.build());
        return result;
    }

    /**
     * Create a DNS response packet to a previous DNS query packet
     *
     * @param dnsQueryPacket Previous DNS query packet
     * @param answers        List of DNS answer records
     * @return DNS response packet
     */
    public static DnsPacket createDNSResponsePacket(DnsPacket dnsQueryPacket, List<DnsResourceRecord> answers) {
        if (answers.size() >= Short.MAX_VALUE) {
            throw new IllegalArgumentException("Too many DNS answer records");
        }

        DnsPacket.Builder dnsBuilder = dnsQueryPacket.getBuilder();
        dnsBuilder
                .response(true)
                .rCode(DnsRCode.NO_ERROR)
                .anCount((short) answers.size())
                .answers(answers);
        return dnsBuilder.build();
    }

    /**
     * Create a UDP packet based on a DNS packet
     *
     * @param udpPacket UDP packet
     * @param dnsPacket DNS packet to encapsulate in UPD packet
     * @return UDP packet containing the input DNS packet in its payload
     */
    public static UdpPacket createUDPPacketFromDNSPacket(IpPacket ipPacket, UdpPacket udpPacket, DnsPacket dnsPacket) {
        UdpPacket.Builder udpBuilder = new UdpPacket.Builder();
        udpBuilder
                .srcPort(udpPacket.getHeader().getDstPort())
                .dstPort(udpPacket.getHeader().getSrcPort())
                .srcAddr(ipPacket.getHeader().getDstAddr())
                .dstAddr(ipPacket.getHeader().getSrcAddr())
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(dnsPacket.getBuilder());

        return udpBuilder.build();
    }

    /**
     * Create a TCP packet based on a DNS packet
     *
     * @param tcpPacket TCP packet
     * @param dnsPacket DNS packet to encapsulate in UPD packet
     * @return TCP packet containing the input DNS packet in its payload
     */
    public static TcpPacket createTCPPacketFromDNSPacket(IpV4Packet ipV4Packet, TcpPacket tcpPacket, DnsPacket dnsPacket) {
        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder();
        tcpBuilder
                .srcPort(tcpPacket.getHeader().getDstPort())
                .dstPort(tcpPacket.getHeader().getSrcPort())
                .srcAddr(ipV4Packet.getHeader().getDstAddr())
                .dstAddr(ipV4Packet.getHeader().getSrcAddr())
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(dnsPacket.getBuilder());

        return tcpBuilder.build();
    }

    /**
     * Create an IpV4 packet based on a transport layer packet
     *
     * @param ipV4Packet      IpV4 packet
     * @param transportPacket packet to encapsulate in IpV4Packet
     * @return IpV4 Packet containing the input UDP packet in its payload
     */
    public static IpV4Packet createIpV4Packet(IpV4Packet ipV4Packet, TransportPacket transportPacket) {
        IpV4Packet.Builder ipBuilder = ipV4Packet.getBuilder();
        ipBuilder
                .srcAddr(ipV4Packet.getHeader().getDstAddr())
                .dstAddr(ipV4Packet.getHeader().getSrcAddr())
                .payloadBuilder(transportPacket.getBuilder())
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        return ipBuilder.build();
    }

    /**
     * Create an Ethernet Packet based on an IpV4 Packet
     *
     * @param ethernetPacket Ethernet packet
     * @param ipV4Packet     IpV4 packet to encapsulate in ethernet packet
     * @return Ethernet packet containing the input IpV4 packet in its payload
     */
    public static EthernetPacket createEthernetPacketFromIpV4Packet(EthernetPacket ethernetPacket, IpV4Packet ipV4Packet) {
        EthernetPacket.Builder etherBuilder = ethernetPacket.getBuilder();
        etherBuilder
                .srcAddr(ethernetPacket.getHeader().getDstAddr())
                .dstAddr(ethernetPacket.getHeader().getSrcAddr())
                .payloadBuilder(ipV4Packet.getBuilder())
                .paddingAtBuild(true);

        return etherBuilder.build();
    }
}
