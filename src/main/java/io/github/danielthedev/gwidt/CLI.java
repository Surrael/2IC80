package io.github.danielthedev.gwidt;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.cli.*;
import org.pcap4j.core.*;

import java.io.IOException;
import java.util.List;

public class CLI {
    private static CommandLine cmd;

    /**
     * Get command line options
     *
     * @return command line options
     */
    private static Options GetOptions() {
        Options options = new Options();

        //======================================= Define options =====================================================//
        Option modeOption = Option.builder("m")
                .longOpt("mode")
                .hasArg()
                .desc("Choose mode: arp poisoning (arp), dns spoofing (dns), or ssl stripping (ssl).")
                .build();

        Option helpOption = Option.builder("h")
                .longOpt("help")
                .desc("Opens this help menu.")
                .build();

        Option interfaceOption = Option.builder("i")
                .longOpt("interface")
                .hasArg()
                .desc("Choose network interface.")
                .build();

        Option hostIPOption = Option.builder()
                .longOpt("hostIP")
                .hasArg()
                .desc("Host IP to be used for ARP poisoning; required for all three attack modes.")
                .build();

        Option hostMacOption = Option.builder()
                .longOpt("hostMac")
                .hasArg()
                .desc("Host MAC to be used for ARP poisoning; required for all three attack modes.")
                .build();

        Option victimIPOption = Option.builder()
                .longOpt("victimIP")
                .hasArg()
                .desc("Victim IP to be used for ARP poisoning; required for all three attack modes.")
                .build();

        Option gatewayIPOption = Option.builder()
                .longOpt("gatewayIP")
                .hasArg()
                .desc("Gateway IP to be used for ARP poisoning; required for all three attack modes.")
                .build();

        Option spoofedDomainOption = Option.builder()
                .longOpt("spoofedDomain")
                .hasArg()
                .desc("Domain to spoof for DNS spoofing; required for dns and ssl modes.")
                .build();

        Option spoofedIPOption = Option.builder()
                .longOpt("spoofedIP")
                .hasArg()
                .desc("Fake IP to spoof for DNS spoofing; required for dns and ssl modes.")
                .build();

        //========================================== Add options =====================================================//
        options.addOption(modeOption)
                .addOption(helpOption)
                .addOption(interfaceOption)
                .addOption(hostIPOption)
                .addOption(hostMacOption)
                .addOption(victimIPOption)
                .addOption(gatewayIPOption)
                .addOption(spoofedDomainOption)
                .addOption(spoofedIPOption);

        return options;
    }

    /**
     * Print help menu
     *
     * @param options command line options
     */
    private static void printHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("GWIDT", options);
    }

    /**
     * List available network interfaces in the terminal
     *
     * @param interfaces list of available network interfaces
     */
    private static void listInterfaces(List<PcapNetworkInterface> interfaces) {
        System.out.println("Available network interfaces:");
        for (int i = 0; i < interfaces.size(); i++) {
            System.out.println(i + ". " + interfaces.get(i).getDescription());
        }
    }

    /**
     * Check if required options are present
     */
    private static void checkAttackOptions() {
        String mode = cmd.getOptionValue("mode");

        if (!(mode.equals("arp") || mode.equals("dns") || mode.equals("ssl"))) {
            System.out.println("Invalid mode. Please choose from arp, dns, or ssl.");
            //printHelp(options);
            System.exit(0);
        }

        if (!(cmd.hasOption("hostIP") && cmd.hasOption("hostMac") && cmd.hasOption("victimIP") && cmd.hasOption("gatewayIP"))) {
            System.out.println("Host IP, host MAC, victim IP, and gateway IP required for all modes.");
            System.exit(0);
        }

        if ((mode.equals("dns") || mode.equals("ssl"))
                && !(cmd.hasOption("spoofedDomain") && cmd.hasOption("spoofedIP"))) {
            System.out.println("DNS spoofing and SSL stripping require domain to spoof, and fake IP to spoof.");
            System.exit(0);
        }
    }

    /**
     * Main method
     *
     * @param args command line arguments
     * @throws PcapNativeException pcap exception
     */
    public static void main(String[] args) throws PcapNativeException {
        CommandLineParser parser = new DefaultParser();
        Options options = GetOptions();
        Input input = new Input();

        // Get available network interfaces
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

        if (interfaces.isEmpty()) {
            System.out.println("No network interfaces found.");
            System.exit(0);
        }

        try {
            cmd = parser.parse(options, args);

            if (cmd.hasOption("help")) {
                printHelp(options);
                System.exit(0);
            }

            if (cmd.hasOption("interface")) {
                String selectedInterface = cmd.getOptionValue("interface");
                NetworkInterface.setDefaultInterface(interfaces.get(Integer.parseInt(selectedInterface)).getDescription());
                System.out.println("listening on interface " + interfaces.get(Integer.parseInt(selectedInterface)).getDescription());
            } else {
                System.out.println("Interface option is required.");
                listInterfaces(interfaces);
            }

            if (cmd.hasOption("mode")) {
                String mode = cmd.getOptionValue("mode");
                checkAttackOptions();
                input.setMode(mode);

                input.setHostIP(cmd.getOptionValue("hostIP"));
                input.setHostMac(cmd.getOptionValue("hostMac"));
                input.setVictimIP(cmd.getOptionValue("victimIP"));
                input.setGatewayIP(cmd.getOptionValue("gatewayIP"));
                input.setSpoofedDomain(cmd.getOptionValue("spoofedDomain"));
                input.setSpoofedIP(cmd.getOptionValue("spoofedIP"));

                NetworkExecutor.initInstance(input.getVictimIP(), input.getGatewayIP());

                switch (mode) {
                    case "arp":
                        ArpPoisoner.ARPPoisoningAttack(input);
                        break;
                    case "dns":
                        ArpPoisoner.ARPPoisoningAttack(input);
                        DnsSpoofer.DNSSpoofingAttack(input);
                        break;
                    case "ssl":
                        ArpPoisoner.ARPPoisoningAttack(input);
                        DnsSpoofer.DNSSpoofingAttack(input);
                        SslStripper.sslStrip(input.getSpoofedDomain());
                        break;
                }
            } else {
                System.out.println("Mode option is required.");
            }
        } catch (ParseException | IOException e) {
            System.err.println("Error parsing command line options: " + e.getMessage());
        }
    }

    /**
     * Input class
     */
    @Setter
    @Getter
    public static class Input {
        private String mode;
        private String hostIP;
        private String hostMac;
        private String victimIP;
        private String gatewayIP;
        private String spoofedDomain;
        private String spoofedIP;
    }
}
