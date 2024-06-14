# Geen WiFi in de Trein (GWIDT)
A tool with ARP spoofing, DNS spoofing and SSL stripping capabilities on local networks. 

## Hardware and Software Requirements

Attacker Machine:
* Capable of running Java class files in a CLI environment.
* Able to find its IP and MAC address.
* Has Npcap installed for Pcap4J library functions.
* Nmap installed for scanning and finding local IP addresses.

Victim Machine:
* A web browser installed (Edge, Chrome, Firefox, or Safari).
* HSTS disabled.
* IPv6 disabled.

## Usage
ARP and DNS spoofing can be run seperately from the CLI, by passing their respective commands:
```bash
-m/--mode arp -victimIP x.x.x.x -hostIP x.x.x.x -hostMac AA-BB-CC-DD-EE-FF -gatewayIP x.x.x.x -i/--interface x
```
```bash
-m/--mode dns -victimIP x.x.x.x -hostIP x.x.x.x -hostMac AA-BB-CC-DD-EE-FF -gatewayIP x.x.x.x -spoofedDomain website.com -spoofedIP x.x.x.x -i/--interface x
```

SSL stripping makes use of both ARP and DNS spoofing concurrently to obtain a MitM position. It can be run using the following command:
```bash
-m/--mode ssl -victimIP x.x.x.x -hostIP x.x.x.x -hostMac AA-BB-CC-DD-EE-FF -gatewayIP x.x.x.x -spoofedDomain website.com -spoofedIP x.x.x.x -i/--interface x
```

All available options and their purpose will be displayed by entering the `-h/--help` flag. Passing no arguments will list all available network interfaces, of which one must be picked by its index in the provided list.

## Limitations
* No IPv6 support.
* HSTS must be disabled on the victim's machine.
* SSL stripping works for a single target domain at a time.

<br><br>
***This project is licensed under the terms of the MIT license.***
