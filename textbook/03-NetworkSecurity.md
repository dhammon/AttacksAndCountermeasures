# Network Security
![](../images/03/globe_internet_connections.jpg)

Technologies that connect computer systems into groups or networks has increased the capabilities of systems and complexity by several orders of magnitude.  It has given rise to the internet and a countless ever expanding range of services.  Governments, organizations and individuals all rely on network systems to conduct a range of tasks that everyone depends on.  This level of complexity and dependency has given rise to many new account vectors for which we will focus on some of them in this chapter.  While it is assumed the reader knows some basic networking, we will revisit general networking technologies and concepts.  We will then introduce some of the technologies and practices used to secure networks.  In the later half of this chapter, we will analyze and exploit common networking technologies.  Not all network security concepts could be covered in one chapter, but the reader will become familiar with the basics of network security and at the same time learning how to approach other network related technologies and systems.

**Objectives**
1. To refresh knowledge on computer networking topics. 
2. Establish network security fundamental theory, threats, and approaches. 
3. Conduct host and service discovery through scanning utilities.
4. Understand security of the address resolution protocol and how to attack it
5. Analyze network packets using Wireshark.
6. Develop and understanding of the basics, security, and attacks against DNS and DHCP
7. Securing and attacking TCP and Wireless systems.

## Network Basics
In the first section of this chapter we'll introduce and discuss common networking topics and technologies.  If you are comfortable with networking, this section may be all a review.  However, we won't cover all networking concepts nor will we go into any deep dives.  The goal of this section is to ensure the foundational knowledge is set before tackling the security of network systems.
### Client/Server Model
So much of networking depends on a requestor and a responder of information.  Usually such a system is referred to as the client/server model.  A **client** is the system requesting information from a **server**.  The term server should not be mistaken for a marketing term applicable to robust computer hardware meant to serve high volumes of content.  While that does describe one type of server it does not encompass all servers.  A server is a concept and any computer system can act as a server - just some are better at it than others.  There are time where a server may also act as a client, for example when a server fetches data from another server it acts as the client.  The term client can mean almost anything requesting the information.  Sometimes a client is a web browser, a computer, or a command line interface (CLI) program.  The following diagram illustrates a computer on the left acting as the client requesting data from a server on the right over the internet.
![[../images/03/client_server.png|Client Server Interaction|350]]
### Network Devices
A computer network typically requires the use of special network equipment to enable the flow of data between computers.  Networks usually provide access to other networks, such as the internet or intranets, via Ethernet cables or wireless signals.  Each computer device which needs access to a network first requires a *network interface card (NIC)* that supports either a wired or wireless connection.  The computer will connect to a *switch* via network cables which has several NICs to support other network computers.  The switch connects computers into a network allowing for traffic to flow between them.  A switch is then connected to a *router* which connects the network to other networks including the internet.  The router tracks all connections between the networks and ensures traffic is routed to the correct destination.  Wireless devices, or *access points (AP)*, can serve as a switch and a router while providing network connectivity without Ethernet cables - at least for connected devices.  Routers and switches can also be nested and chained together for the purpose of creating layers of networks.  Networks can even be logical, or virtualized, into *virtualized local area networks (VLAN)* through routers and switches.  While routers can provide some basic security by defining rules that allow some traffic to travers networks and block other types of traffic, a security device called a *firewall* is better equipped for the task as it can provide many other security feature which we will review a little later in this chapter.  Firewalls are then connected to a modem that provides and internet connection.

Each of these devices can be individual pieces of equipment or lumped together into a single device.  Usually consumer devices have the router, switch, wireless, firewall, and modem all in a single device sometimes called a *gateway* that is provided by an *internet service provider*.  Commercial networks usually have each of these devices separate for ease of management, support, and scalability.  As enterprise networks are usually much larger than a home network, it is best to manage each function in a separate device should one ever need to be replaced or expanded - thus avoiding the need to replace an entire network stack.
![[../images/03/network_equipment.png|Network Equipment|600]]
The image above displays small network appliances.  Starting from the top left and moving to the right and then the second row we have:
1. Netgear Switch
2. Tplink Router
3. Intel NIC
4. Ubuquity Access Point
5. Protectili Firewall
These devices are what you might find in a home or small office.  Enterprise equipment is much larger and would typically be placed on a *network rack* with organized and color coordinated cables.
### LAN/WAN
As mentioned earlier, a router provides the connection of a network to other networks and often the internet.  The router has several NICs with at least one of them dedicated to the *wide area network (WAN)* and the other NICs dedicated to *local area networks (LAN)*.  Network security administrators will refer to attacks coming from the WAN side (internet) or the LAN side (internal network) to indicate the direction of an attack.  For example, a router might have a built in web server that supports a management *graphical user interface (GUI)*.  A network administrator would want to ensure this web GUI is not exposed WAN side to ensure anonymous internet users couldn't access it.  The following graphic illustrates the connection of two computer networks using routers WAN interfaces over the internet.
![[../images/03/wan_lan.png|LANs Connected Over WAN|500]]
### Network Topologies
- peer to peer
- bus
- ring
- tree
- star
- mesh
### MAC
- meda access control
- network interface ID
- organization unique identifier (OUI)
### IPv4
Class ranges
### RFC 1918
private IP ranges
### Subnetting
- prefix, subnet, host
### Classless Inter-domain Routing (CIDR)
- common cidr ranges
- interpret prefix, host ID, IP count, and subnet mask
### Network Address Translation (NAT)
### Dynamic Host Configuration Protocol (DHCP)
- DORA (Discover, Offer, Request, Acknowledge)
### Ports, Protocols, Services
- Port=window
- Protocol = exchange money and goods
- Service  taking orders, money handling, goods dispensing
### Transmission Control Protocol (TCP)
- three way handshake
- SYNchronize
- ACKnowledge
### User Datagram Protocol (UDP)
- REQuest
- RESponse
### Open Systems Interconnection (OSI)
- 7; application; http, smtp, dhcp, ftp, telnet
- 6; presentation; ascii, tls/ssl
- 5; session; rpc, sql, nfs, netbios
- 5; transport; tcp, udp
- 3; network; ip, icmp, bgp, ospf, ipsec, router
- 2; data link; ppp, arp, switch
- 1; physical; cable
### Packets
### Encapsulation/Decapsulation

### Network Utilities
>[!activity] Activity - Network Utilities

## Network Security
Definition - Cisco quote
### Risks
- CIA triad
	- unauthorized access
	- denial of service
	- data modification
### Network Segmentation
- blast radius
- VLANS - trunks and subnets
- DMZ
- firewall rules
### Firewall Stateless Inspection
- Unidirectional
- only looks at header port and IP
### Firewall Stateful Inspection
- Enables port and IP but also session and service states
- continuous
- Dynamic rules based on state
### Firewall Next Gen
- TLS inspection/deep packet inspection
- antivirus
- application and identity based control
- vpn concentrators
- IDS/IPS
- DoS protection
### VPNs
- Generic routing encapsulation (GRE) tunneling
	- Split tunnel - part of traffic
	- full tunnel - all traffic
- IPsec (encryption)
	- site to site
- TLS
- Virtual Interfaces
	- TUN - IP packets (layer 3)
	- TAP - ethernet frames (layer 2)
### Port Scanning
> [!activity] Activity - NMAP

### Wireshark
wireshark basics
>[!activity] Activity - Wireshark


---

Chapter split?

---

## ARP
ARP Basics
### ARP Protocol
### ARP Cache/Table
> [!activity] Activity - ARP
### MiTM ARP Attacks
### Securing ARP
>[!activity] Activity - ARPSpoof

## DNS
### DNS Infrastructure
### DNS Records
### Zone Transfer
>[!activity] Activity - Zone File
### DNS Threats
- local cache poisoning
- remote cache poisoning
- malicious DNS server
- DNS Rebinding
- DNS Tunneling Exfiltration
- DNS Flood Attacks
>[!activity] Activity - DNS Spoofing

## DHCP
### DORA
### DCHP Release
### DHCP Risks
### DHCP Attacks
- DHCP Starvation
- DHCP Spoofing
>[!activity] Activity - DHCP Spoofing Attack
### DHCP Security
- DHCP Snooping
- Dynamic ARP Inspection (DAI)

## TCP
basics
### TCP Threats
### TCP Security
>[!activity] Activity - TCP Reset Attack

## Wireless
WiFi Basics
### WiFi Architectures
### WiFi Generations
### WiFi Threats
### WiFi Security
### WiFi Encryption Standards
### WiFi Attacks
- Deauth
- Rouge AP
- Evil Twin
- Encryption Cracking
>[!activity] Activity - WiFi WEP Cracking

