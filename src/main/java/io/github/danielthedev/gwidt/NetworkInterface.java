package io.github.danielthedev.gwidt;

import lombok.Setter;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.util.function.Consumer;

public class NetworkInterface<T> extends Thread {

    private static String DEFAULT_INTERFACE = "Intel(R) I211 Gigabit Network Connection";
    private static final int snapshotLength = 65536; // in bytes
    private static final int readTimeout = 50;
    private final PcapHandle handle;
    private final String name;
    private FilterPipeline<T> filterPipeline;

    @Setter
    private UnsafeConsumer<T> packetListener;

    /**
     * Constructor
     *
     * @param name           instance name
     * @param filter         filter to apply to the network interface
     * @param filterPipeline filter pipeline to apply to the network interface
     * @throws PcapNativeException if network interface is invalid
     * @throws NotOpenException    if network interface is not open
     */
    public NetworkInterface(String name, String filter, FilterPipeline<T> filterPipeline) throws PcapNativeException, NotOpenException {
        this.filterPipeline = filterPipeline;
        this.name = name;
        PcapNetworkInterface device = Pcaps.findAllDevs().stream().filter(adapter -> adapter.getDescription().equals(DEFAULT_INTERFACE)).findFirst().get();
        this.handle = device.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, readTimeout);
        this.handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        this.start();
    }

    /**
     * Set the default network interface
     *
     * @param defaultInterface the default network interface to be used by all instances
     */
    public static void setDefaultInterface(String defaultInterface) {
        NetworkInterface.DEFAULT_INTERFACE = defaultInterface;
    }

    /**
     * Send a packet over the default interface
     *
     * @param packet the packet to be sent
     */
    public void sendPacket(Packet packet) {
        try {
            if (this.handle != null) this.handle.sendPacket(packet);
            else System.err.println("could not send packet");
        } catch (PcapNativeException | NotOpenException e) {
            throw new RuntimeException(e);
        }
    }

    public void removePacketListener() {
        this.packetListener = null;
    }

    /**
     * Run the network interface with the constructed packet listener
     */
    @Override
    public void run() {
        try {
            this.handle.loop(-1, (PacketListener) packet -> {
                if (this.packetListener != null) {
                    T result = this.filterPipeline.readPacket(packet);
                    if (result != null) {
                        try {
                            this.packetListener.accept(result);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
            });
        } catch (PcapNativeException | InterruptedException | NotOpenException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Filter pipeline interface
     *
     * @param <T> pipeline return type
     */
    interface FilterPipeline<T> {
        T readPacket(Packet packet);
    }
}
