<span class="chapter-banner">Chapter 3</span>
# Network Security

<div class="image-crop">
  <img src="../images/03/globe_internet_connections.jpg">
</div>

**Objectives**
1. Refresh knowledge on computer networking topics. 
2. Establish network security fundamental theory, threats, and approaches. 
3. Conduct host and service discovery through scanning utilities.
4. Analyze network packets using Wireshark.
5. Crack the password of a wireless WEP network.

Technologies that connect computer systems into networks have increased the capabilities and complexities of software by several orders of magnitude.  They have given rise to the internet and an ever-growing range of network services and web applications.  Governments, organizations, and individuals all rely on network systems to conduct commerce, business, and communication.  The complexity of network systems increases the attack surface and security risks.  This chapter will cover basic networking concepts and lay the foundation for network security principles.  While it is assumed the reader knows some basic networking, I will review general networking technologies and concepts.  I will then introduce some of the technologies and practices used to secure networks.  Not all network security concepts could be covered in one chapter; however, the reader will become familiar with the basics of network security and simultaneously learn how to approach other network related technologies and systems.
## Network Basics
In the first section of this chapter, I will introduce common networking topics and technologies.  If you are comfortable with networking, this section may be a nice refresher.  However, I will not cover all networking concepts, nor will I go into any deep dives on a particular subject.  The goal of this section is to ensure the reader is equipped with the foundational knowledge needed before tackling network security concepts.
### Client/Server Model
So much of networking depends on the request and response of data.  Such a system is usually referred to as the client/server model.  A **client** is the system requesting information from a **server**.  You might imagine that a server is a big and expensive piece of hardware in a data center somewhere, reserved only for commercial entities, but that is not the case.  A server is a concept that can be applied to any computing device.  There are even times when a server also acts as a client, such as when a server fetches data from another server.  The term client can mean almost anything requesting information over a network.  A client can be a web browser, computer, or a command line interface (CLI) program.  The following diagram illustrates a computer on the left acting as the client requesting data from a server on the right over the internet.

![[../images/03/client_server.png|Client Server Interaction|350]]

### Network Devices
A computer network typically requires the use of special network equipment to enable the flow of data between computers.  Networks usually provide access to other networks, such as the internet or intranets, via Ethernet cables or wireless signals.  Each computing device needing access to a network first requires a *network interface card (NIC)* that supports a wired or wireless connectivity.  Using network cables, a computer may connect to a *switch* which has several NICs that support other networked devices.  The switch connects devices within a network allowing for traffic to flow between them.  A switch is then connected to a *router* establishing a network that can be bridged to other networks such as the internet.  The router tracks all connections between the networks and ensures traffic is sent to the correct destination within its immediate range.  Wireless devices, or *access points (AP)*, can serve as a switch and a router while providing network connectivity without the use of Ethernet cables.  Routers and switches can also be nested and chained together to create layers of multiple networks.  Networks can even be logically, or virtualized, into *virtualized local area networks (VLAN)* using managed routers and switches.

Routers and switches can provide some basic security by defining rules that allow or block traffic traversing networks.  However, another device called a *firewall* has richer security features and capabilities.  They are often placed between networks to control the security of a network's perimeter.  Firewalls are then connected to a modem that provides an internet connection.

Each of these devices can be individual pieces of equipment or lumped together into a single device.  Many consumer devices have the router, switch, wireless, firewall, and modem in a single device called a *gateway* commonly provided by an *internet service provider (ISP)*.  Such all-in-one devices are usually insufficient for commercial networks as they are limited by features, capacity, and support.  Larger networks will therefore have each network component, such as switches and routers, as standalone devices that can be individually managed.  This provides network administrators with more flexibility when scaling the size of the network or performing maintenance and replacements on equipment.

![[../images/03/network_equipment.png|Network Equipment (source Amazon)|600]]

The image above consists of small consumer grade network devices.  These, and many other brands like them, are used for home or small business use.  The devices are listed in order starting from the top left:

1. Netgear Switch
2. Tplink Router
3. Intel NIC
4. Ubiquity Access Point
5. Protectili Firewall

They could be consolidated into a single device called a gateway, mentioned earlier in this section.  Not shown in the image is enterprise network equipment.  This equipment is much larger and would typically be placed on a *network rack* with organized and color-coded Ethernet cables.  An office building with several floors might dedicate a room to a few six-foot racks that house all the network equipment and wiring needed to support its tenants.
### LAN/WAN
As mentioned earlier, a router provides the connection of a network to other networks, including the internet.  The router has several interfaces with at least one of them dedicated to the *wide area network (WAN)* and the other interfaces dedicated to *local area networks (LAN)*.  The following graphic illustrates the connection of two computer networks using router WAN interfaces over the internet.
![[../images/03/wan_lan.png|LANs Connected Over WAN|500]]

Network security administrators will refer to attacks coming from the WAN side (internet) or the LAN side (internal network) to indicate the source of an attack.  For example, a router might have a built-in web server that serves a *graphical user interface (GUI)* to manage the device's settings.  An administrator would want to ensure this web GUI is not exposed WAN side to prevent anonymous internet users from accessing it.
### Network Topologies
There are several patterns or designs for connecting computers to a network, each with its benefits and disadvantages.  Network administrators determine which design to use when planning networks.  The following graphic displays some of the common network topologies explored in this section.

![[../images/03/topologies.png|Network Topologies|600]]

The **peer-to-peer (P2P)** network uses a *cross-over cable* that allows two computers to communicate directly with one another without the need for any networking equipment, such as a switch.  This straightforward design is elegant but not scalable.  Of course, this configuration is limited in that no other devices can be connected to the network.  Modern network adapters support *auto-MDIX* that allow P2P connections using regular Ethernet cables.

>[!story] Story - Peer-to-Peer Networking Doom
>When I was a kid int he 90's, the PC game Doom was released and supported multiplayer through a network.  I have fond memories of my dad connecting his computer with my computer in the basement using a peer-to-peer connection and then playing deathmatches against each other - he did not stand a chance.

Computers can also be connected into a **ring** network where each device connects to the next until a full circle is completed.  This method allows you to include more computers in a peer-to-peer pattern but has the disadvantage of every device relaying every message.  If scaled, the network grows increasingly slower due to the number of hops to get from one computer to the next.  A slightly better alternative is via the **bus** pattern, in which each computer in the network connects to a backbone; however, it grows increasingly unstable with the addition of new devices.  Any device could tap into the traffic of all other devices.

Ring and bus designs require the transmission of data flow through several devices before reaching the final destination.  An adaptation to the ring topology, called **mesh**, allows each device to directly connect to every other device on the network.  While this potentially solves some network delays and security concerns by avoiding transmissions from having to be routed through multiple computers, it also raises scaling concerns and limitations.  The number of connections in a mesh network grows increasing larger for each device added to the network.

Combining network patterns results in **hybrid** networks being formed.  For example, a star and tree network can be used together to create a larger multi-network.  Most modern network designs now use a **tree** and a **star** pattern.  The tree pattern is supported with network switches as a central point for network communications.  This also enables the ability to expand the network size by chaining multiple switches.  Similarly, the star pattern is used with routers to connect multiple tree networks together.

### MAC Addresses
Every network interface card (NIC) has a unique address called a **media access control (MAC)** address.  MAC addresses are assigned to the NIC during the manufacturing process and are unique and static (will not change).  Therefore, a MAC address is like your home address, as they are both unique, static, and ensure discoverability.  The address is composed of six octets displayed in hexadecimal format.  Each octet is eight bits and the total number of bits in a MAC address is 48, or six bytes.  The first half of the MAC, or the first three octets, is called the **organization unique identifier (OUI)** and identifies the manufacturer of the device.  For example, the OUI `FC:F8:AE` is one of many associated with the manufacturer Intel.  Knowing a device's MAC address allows you to derive information about the device type by looking up the identity of the manufacturer.  This can be useful information to network administrators, and attackers, when surveying devices connected to a network.

The remaining bytes in the MAC address, not associated with the OUI, are a unique sequence that distinguishes one NIC from another on the network.  As mentioned earlier, a NIC's MAC address is supposed to be static, or never changing, which avoids address collisions where more than one device has the same MAC address.  However, it is possible to change a NIC's assigned MAC address or convince other devices on the network that another device has a different MAC than the one assigned to it by the manufacturer, which could subvert the normal operation of networks.  We will explore this concept in greater detail later in the chapter.

MAC addresses are the primary identifier used by network switches to organize and move traffic.  A network switch maintains a table of connected device MAC addresses, so it knows which switch NIC to send the traffic.  MACs are also used in the *address resolution protocol (ARP)* which associates MAC addresses to *internet protocol (IP)* addresses.  ARP and IPs will also be explored in further detail later in this chapter.
### IPv4
It would not be feasible for network devices to maintain a list of all MAC addresses for all devices in all networks.  Therefore, a grouping of networks and devices is needed to organize where traffic needs to be sent.  The **internet protocol version 4 (IPv4)** specification enables the organization of networks through a 32 bit address, presented using decimal format, divided into a *network prefix* which identifies the network class, a *subnet* which identifies the network within the class, and a *host number* that specifies the device on that network.  IP addresses are used to route traffic between networks while switches associate them with MAC addresses to ensure traffic reaches its destination on a network.  IP addresses are grouped together into classes, as demonstrated in the following table.

| Class | Network Prefix Range |
| ----- | -------------------- |
| A     | 0-127                |
| B     | 128-191              |
| C     | 192-223              |
| D     | 224-239              |
| E     | 240-255              |

IPv4 is presented in dot-decimal notation consisting of four octets.  Each octet goes up to the value 255 which is calculated by two to the eighth power (2^8) yielding 256, but since we start counting at zero, the highest indexed number used is 255.  The first octet defines which class the address belongs to and is managed by the *Internet Assigned Numbers Authority (IANA)*.  Several blocks of IP ranges are used for specific purposes and are handled appropriately by compliant network devices.  The rules that govern networking are cataloged as *request for comments (RFC)* which detail specifications everyone must follow.  For example, and worth committing to memory, RFC 1918 specifies which IP address ranges are designated for private networks.  This implies that all other network prefix ranges are used for public networks or other defined purposes.  Internet routers usually will not route private IP addresses; as these addresses are used by every network making them ambiguous while on the internet.  Chances are, the LAN interface on your home router is 192.168.1.1, and so is mine.  It is therefore prudent that we agree on which IP addresses are public, and which are private to ensure routing consistency on the internet.  The following table summarizes the RFC 1918 address space available to private networks.

| Start | End | Available Addresses |
| ---- | ---- | ---- |
| 10.0.0.0 | 10.255.255.255 | 16,777,216 |
| 172.16.0.0 | 172.31.255.255 | 1,058,576 |
| 192.168.0.0 | 192.168.255.255 | 65,536 |

The ability to see an address and instantly know if it is a public or private IP address makes a world of difference to network troubleshooting.

> [!note] Note - IPv6 
> While we will not be covering IP version 6 (*IPv6*), it is worth at least a mention in this chapter.  IPv6 solves the same networking goals as IPv4 but provides a far greater number of unique addresses.  It also consolidates and streamlines several networking features and services.  As of the writing of this text, IPv4 is much more popular in use in the United States, so IPv4 remains the focus of this chapter.  However, IPv6 has its own security implications and is a great topic to research further.
### Subnetting
As discussed earlier, the IPv4 address space is divided into prefix, subnet, and host sections.  The prefix and subnet sections are usually combined and referred to as the network section of an IP address.  The prefix will identify the network's class, while the subnet indicates which network is associated with the IP address.  The final octet of the IP address is assigned to a specific host on that network.  No two devices on the same network should share the same IP address; otherwise, network issues will occur.  Using the IP address `192.168.1.5` as an example, the first two octets with the value of `192.168` is the prefix and identifies this is a private IP address.  The third octet with the value of `1` is the subnet.  The fourth and last octet is the host and has a value of `5`.  We can conclude that the host is in the `1` subnet of a private network.

Determining the subnet requires knowing the *subnet mask*, which is advertised as part of a network transmission.  The subnet mask is represented in four octets that describe up to 256 bits each, just like an IP address.  It is used to define the number of networks and their relative sizes and might look something like `255.255.0.0`.  The subnet section of an IPv4 address can extend beyond a single octet depending on the network type.  Most of the time, a network engineer designs subnets in a manner that is easy to understand to avoid confusion and results in dividing or expanding beyond a single octet or decimal.  Let's illustrate with some examples of potential subnet ranges:

| Start       | End           | Number of Hosts | Subnet Mask     | Use                                                                                                                     |
| ----------- | ------------- | --------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------- |
| 192.168.0.0 | 192.168.0.255 | 256             | 255.255.255.0   | Most common because it is easy using 3 octet single value as the subnet.  The next network could be 2 then 3 and so on. |
| 192.168.0.0 | 192.168.0.4   | 4               | 255.255.255.252 | Small network                                                                                                           |
| 192.168.0.0 | 192.168.1.255 | 512             | 255.255.254.0   | Larger network                                                                                                          |

Technically, the number of usable hosts are two less than what is displayed in the table; as the first and last address in a subnet are reserved for dedicated networking purposes.  Network administrators can divide the subnet space any way they need to accommodate limited IP addresses and desired number of hosts within a network.  You must be able to interpret networks while troubleshooting or evaluating network security.  Understanding the number and size of available networks is crucial for being able to connect, secure, or attack devices on those networks.
### Classless Inter-domain Routing (CIDR)
Network administrators and systems can also use **classless inter-domain routing (CIDR)** notation to define the number and size of networks.  Like subnet masks, CIDR notation has the benefit of being simpler to communicate, as it consists of only one number.  Anyone wanting to understand how a network is divided would therefore need to know the CIDR, or the subnet mask. 

CIDR defines subnet ranges by a *prefix* value which is a forward slash followed by a number that represents the number of bits used for the network.  For example, `192.168.1.0/24` represents the IP range `192.168.1.0 - 192.168.1.255`.  The *bit range*, number after the forward slash, represents the number of bits that establish the prefix portion of the IP address.  The *host id*, is the number of bits that determine the number of hosts on that network.  It is calculated by taking the total bit range (32) minus the prefix.  Using the last example, calculating the host id is a matter of 32 minus the prefix `/24` which is 8.  Continuing with this same example, to calculate the number of hosts, raise 2 to the power of the host ID value (8), resulting in 256 hosts.  The following table itemizes some of the more common CIDR prefixes, host IDs, IP counts, and associated subnet masks.

| Prefix | Host ID | IP Count | Subnet Mask |
| ---- | ---- | ---- | ---- |
| /32 | 0 | - | 255.255.255.255 |
| /28 | 4 | 14 | 255.255.255.240 |
| /24 | 8 | 254 | 255.255.255.0 |
| /16 | 16 | 65,534 | 255.255.0.0 |
| /8 | 24 | 16,777,214 | 255.0.0.0 |
### Network Address Translation (NAT)
A router's WAN and LAN interfaces, or NICs, like any network interface, is assigned an IP address.  The IP address of the WAN interface, facing the internet, is provided as a public IP address.  Your home router's WAN interface is assigned a public IP address which serves as the address to which internet resources can reach your network.  Similarly, LAN interfaces on a router are assigned an RFC 1918 private IP address.  This enables a network to have many devices connected to the internet while only requiring the network to have one public IP address.  Otherwise, every internet connected device would require a dedicated public IP address, and we would have run out of public IP addresses long ago since there are far more NICs than there are IP addresses.

There are not enough IPv4 addresses for every NIC in the world to have their own dedicated and unique IPv4 address.  This was quickly realized during the dawn of the internet and solutions were needed.  This problem required a solution that allowed multiple devices to have the same IP address and not have collisions on the wider internet.  Alongside RFC 1918 mentioned earlier in this chapter, the design of a **network address translation (NAT)** system was developed.  A router provides the NAT service where LAN address requests to the public address space on the internet are tracked within a table.  The router adds entries to the table whenever a device LAN side makes a request WAN side.  When an internet address responds to the router, the router looks up which LAN address requested the internet resource and routes the inbound traffic to the appropriate private network.  The following diagram illustrates this setup with a private computer on the left within a network router that is internet connected.

![[../images/03/nat.png|Network Address Translation|450]]

When the private computer at `192.168.1.5` reaches out to the internet resource at `49.123.1.5`, the request first reaches the router's LAN interface at `192.168.1.1`.  Once the request reaches the router, a record is logged within its NAT table.  The router strips the private computer's IP address from the request, replaces that IP address with its WAN address `116.45.12.99`, and it then forwards the traffic out to the internet.  The internet server at `49.123.1.5` will receive the request and then send a response to the router's WAN interface address at `116.45.12.99`.  The server does not know the private IP address of the computer because this detail was stripped off the request by the router.  The router then receives the server's response and looks up which LAN address made the request on the NAT table and then forwards the response back to that original requestor.  This architecture allows for many devices in a LAN to share a single public IP address assigned to the router's WAN interface - thus reducing the number of public IP addresses consumed and providing some anonymity for hosts making internet requests.

Devices making network requests will open a *network socket* represented by a port number to receive a response.  This port number is also documented alongside IP addresses within the NAT table on the router.  The port number is retained within the request that is forwarded to the internet server that will provide that same port number in its response.  This continuity allows the router to identify the LAN side resource that made the original request because they bound the port in the NAT table.  Without the port number binding, the router would not know which LAN side resource made the request as there can be many devices on a network connecting to a single internet server!
### Ports, Protocols, Services
Networked devices communicate with each other via **protocols** that are predetermined rules of how and what can be communicated.  Protocols establish requirements of what needs to be included in a communication, how they are initiated, and how they are concluded.  A protocol is much like how people interact with each other during common scenarios.  For example, a person initiating a phone conversation dials a number and waits for the other end to pick up.  The person receiving the call addresses the caller with the greeting "hello".  Once the call is answered and greeted, the caller also states "hello" and then introduces themselves and explains why they are calling.  This is an example of protocol with which we should be very familiar.  Computer or networking protocols work based on the same principles of established procedure.  There are many types of networking protocols, and we will review several in this and the next chapter.

Before a computer engages another computer via network transmissions, it must first determine which device it wants to engage.  The requesting computer identifies the IP address of the system it is targeting.  But IP address alone is not enough to establish a communication, and the requesting device must also identify to which **port** to connect.  A port is represented by a number between 0 and 65535.  The port numbers 0-1023 are associated with well-known services, port numbers 1024-49151 are registered for specific purposes, and the port range 49152-65535 are used as ephemeral ports such as those used for outbound requests during NAT.

These ephemeral ports are used by a requestor making an outbound connection so it can keep track of requests it makes and have an avenue to receive responses.  If an IP address is like the address to a house, ports are like the windows and doors of the house.  If a computer has an open port, it usually means it has a program running as a **service** that is configured to respond to connections to that port.  For example, port 80 is commonly used with the *hypertext transmission protocol (HTTP)* and a webserver listens for incoming connections to its port 80 to serve web pages.

> [!tip] Tip - Common Services and Ports
> There are many common ports and services a proficient security professional should know by memory.  For example, one should know which port is commonly associated with *file transfer protocol (FTP)* and which service is commonly associated with port 22.  Consider committing the following table to memory:
> 
> | Port | Service/Protocol | | Port | Service/Protocol |
> | --- | --- | --- | --- | --- |
> | 21 | File Transfer Protocol (FTP) | | 110 | Post Office Protocol (POP)
> | 22 | Secure Shell (SSH) | | 139 | NetBIOS |
> | 23 | Telnet | | 143 | Internet Message Access Protocol (IMAP) |
> | 25 | Simple Mail Transfer Protocol (SMTP)| | 443 | Hypertext Transfer Protocol Secure (HTTPS) |
> | 53 | Domain Name System (DNS) | | 3306 | MySQL |
> | 80 | Hypertext transfer Protocol (HTTP) | | 3389 | Remote Desktop Protocol (RDP) |
> | 88 | Kerberos | |5432 | PostgreSQL |

Ports could be open without a listening service and services can listen to closed ports - in either case, communication over these ports fails.  This is an important concept to consider while troubleshooting networks.  The client/server model requires that the components of ports, services and protocols all work together to deliver information.  If any one of these components fails, the transfer of information will not occur and will result in some type of network error.

I like using a non-digital analogy to illustrate ports, protocols, and services in terms that anyone living in the United States can related to - the fast-food drive thru.  You enter a drive thru and pull up to a speaker box (port) and patiently await an acknowledgment by the drive thru worker (service) from the sensors that detect a car has pulled up.  The worker greets you and you place your order (protocol).  After you have placed your order, you pull up to the 1st window (port) and do not see anyone on the other side (no service!).  You wait a moment before realizing there is a second window, and you decide to pull up to it.  Once stopped at the second window (port), another worker (service) greets you, collects payment, and delivers you your order (protocol).
### Transmission Control Protocol (TCP) and User Datagram Protocol (UDP)
There are two core protocols that encapsulate the common protocols, like the ones described in the last section, called the **Transmission Control Protocol (TCP)** and the **User Datagram Protocol (UDP)**.  TCP and UDP have distinct characteristics that can be useful depending on the need.

TCP uses a *three-way handshake* to establish connections between systems which verifies that the connection is made to both parties.  As illustrated in the figure below, the client initiates a request by sending a *synchronize (SYN)* request to the server.  Upon receiving the request, the server responds with a *synchronize + acknowledge (SYN+ACK)* response back to the client.  The client receives the SYN+ACK and then sends an ACK packet to the server finalizing the connection.

![[../images/03/three_way_handshake.png|TCP Three-Way Handshake|250]]

The handshake ensures both client and server have established the connection and then transmission of other requests and response can resume.  The downside to TCP is that it takes some time to make the round-trip SYN, SYN+ACK, and ACK transmissions.  UDP on the other hand does not have this time delay as senders transmit *requests (REQ)* assuming the server receives them.  Servers may send a *response (RES)* made to them but the protocol is less dependable, although much faster than TCP.

![[../images/03/udp_req_res.png|UDP Request Response|250]]

### Open Systems Interconnection (OSI)
Network transmissions can be modeled using categories as layers that describe how requests and responses are generated and consumed.  The popular **Open Systems Interconnection (OSI)** model defines seven layers used within a network device to explain how messages are handled.  Typically, a message starts at a higher-level protocol and is then passed to each consecutive lower layer before being converted to digital signals sent across a wired or wireless network.  Inversely, the receiver of the message first interacts with the message at the lowest layer and passes it up consecutively to the highest layer for interpretation.  The following table lists the seven layers of the OSI model, corresponding protocols, and network equipment where applicable.

| Layer Number | Layer Name   | Protocol                      | Device         |
| ------------ | ------------ | ----------------------------- | -------------- |
| 7            | Application  | HTTP, SMTP, DHCP, FTP, Telnet | -              |
| 6            | Presentation | ASCII, TLS/SSL                | -              |
| 5            | Session      | RPC, SQL, NFS, NetBIOS        | -              |
| 4            | Transport    | TCP, UDP                      | -              |
| 3            | Network      | IP, ICMP, BGP, OSPF, IPSec    | Router         |
| 2            | Data Link    | PPP, ARP                      | Switch         |
| 1            | Physical     | -                             | Ethernet Cable |

>[!info] Info - TCP/IP Model
>The original but now less popular **TCP/IP** network layer model follows a similar pattern as the OSI model but has four layers instead of seven.  The top layer of TCP/IP groups the OSI's Application, Presentation, and Session layers into a single Application layer.  The Transport and Network layers are consistent whereas the last layer groups the Data Link and Physical layers into a single Network Interface layer.  Reference to either model is correct, but it is important to ensure they are used consistently to avoid confusion.
### Packets
The term **packet** is referred to as any message sent between computers or within any layer of the OSI model.  While convenient, it is technically untrue as some layers have different names for the messages.  Messages from higher layer protocols are referred to as *packet segments* that include a data section and a checksum to verify the message's integrity.  These segments are passed to the network layer where they are wrapped with a header detailing information about its source destination and port, thereon known as a *packet*.  The packet is sent further down the stack to the data link layer where the MAC address is added within another header known as a *frame*.  

Each layer has its own networking requirements that are used to prepare or deliver a message.  The layer will *wrap*, or **encapsulate**, a message with data needed for that layer and it will strip, or **decapsulate**, that same data when the message is received at a higher layer.  Messages that are too large to fit within one "packet" are broken up and sequentially labeled into what are called *packet fragments*.  These fragments are then reassembled into a complete message by the receiving device.  The receiving device will make a request for the missing packet from the sender if any of the sent fragments become corrupt, fail checksum validations, go missing, or experience any other network errors.
### Analyzing Packets with Wireshark
Wireshark is a free tool that empowers users to capture and analyze packets on a device.  It is extremely useful when troubleshooting or exploring network communications as it collects and organizes all information from every packet.  It allows the user to identify the types of packets being sent and received, capture data on multiple OSI layers, and extract files that flowed through the NIC.  Features of the tool include filtering, statistical reports, encryption keys, and many more.

>[!activity] Activity 3.1 - Wireshark
>Let's explore the Wireshark interface using the Kali VM.  To start Wireshark, I'll launch a terminal and enter the command `sudo wireshark`.
>![[../images/03/wireshark_start.png|Starting Wireshark]]
>To start capturing packets, select the `eth0` network interface and then the "blue fin" icon in the upper left corner of the screen.
>![[../images/03/wireshark_capture.png|Start Packet Capture|500]]
>Almost immediately we begin seeing packet entries in the top primary pane.  We can stop the capture at any time by pressing the red square next to the capture button in the upper left corner.  The primary pane lists each captured packet in a table with the first column displaying the relative capture order, time, source IP or MAC, destination IP or MAC, the protocol and general packet info.  The bottom left pane displays a structured object of a selected packet, and the bottom right pane shows the hexadecimal format of the packet.
>![[../images/03/wireshark_packets.png|Packets Captured|700]]
>I find that adding the source and destination ports as columns to the main pane is useful.  To alter the displayed columns, right-click the column header, select `Column Preferences` from the context menu.
>![[../images/03/wireshark_col_prefs.png|Wireshark Column Preferences|400]]
> With the column preferences opened, push the "+" add button at the bottom of the window and double click `Number`.  Select Destination Port from the drop-down menu then double click the title of the added row and enter `DstPort`.  Repeat these steps and add another column for the Source Port.  Next, drag and drop the newly created columns next to their respective columns that hold the address space.  Your Preferences window should look like the one below once complete.  Press OK to complete the changes.
> ![[../images/03/wireshark_add_col.png|Wireshark Add Columns|500]]
> Observe that the main pane now shows the source and destination ports for each packet!  Next, I open the web browser within the VM and navigate to `http://google.com`.  Afterwards, I apply the `http` filter in Wireshark to only display HTTP packets that have been captured.
> ![[../images/03/wireshark_filter.png|Filtering HTTP Packets|500]]
> Wireshark can display domain names instead of the IP address which will help us identify which of these packets are related to the Google domain.  To enable this setting, go to Edit and Preferences to launch the preference window.  Then select `Name Resolution` from the left navigation menu and check the `Resolve network (IP) addresses` option.  Press OK to apply the setting.
> ![[../images/03/wireshark_resolve.png|Wireshark Name Resolution|500]]
> Notice that many of the IP addresses displayed in the main pane now display domain names instead of IP addresses!  The first packets do not look related to Google.  Scrolling down reveals several Google related packets.  To open the *stream*, or related packets, select the first packet and right click to open the context menu.  Select `Follow` and then `HTTP Stream` to open the stream.
> ![[../images/03/wireshark_follow.png|Follow Stream Feature|500]]
> The stream window opens and displays the request (red text) and the response (blue text) and any subsequent related packets. 
> ![[../images/03/wireshark_stream.png|HTTP Stream|500]]
> I close the stream and delete the `http` filter then press enter to display all captured packets.  Another excellent feature of Wireshark is the statistics reporting.  These reports can be helpful to get a general idea of the types of packets that were captured and to potentially identify any unusual protocols or connections that are made.  Select the `Statistics` menu and then choose `Conversations` to open the report.  Press the `Name Resolution` option on the left menu and then choose the `IPv4` tab and observe the statistics from our connection to google.com.
> ![[../images/03/wireshark_endpoints.png|Wireshark Statistics Endpoint Report|500]]
> There are many other useful features of Wireshark.  We will revisit the tool again later in the textbook during the Malware Analysis section where we will carve files from packet captures.
> 
### Network Utilities
Troubleshooting network issues is a common task for many technology professionals.  These skills are beneficial to network administrators, developers, security professionals, and anyone in between.  Windows and Linux systems usually come pre-installed with several tools that are useful for identifying network configurations and assisting with troubleshooting efforts.  These tools can also be used by attackers to explore the network of a compromised machine.

>[!activity] Activity 3.2 - Network Utilities
>Let's explore using several network utilities on the Windows and Kali VMs.  Each machine's network settings need to be in `Bridge Adapter` mode for this demonstration.  This will ensure that each machine has its own IP address and is on the same network as the host.
>![[../images/03/virtualbox_network_example.png|VirtualBox VM Network Setting|500]]
>
>The network configurations of a system consist of the MAC address, IP address, and other information for each network interface on the device.  From within a terminal, I use the `ip address` or `ip a` command on the Kali VM and see that the machine has two interfaces `lo` and `eth0`.
>![[../images/03/activity_util_kali_ip.png|Linux IP Configuration|600]]
>The `eth0`, or Ethernet, interface is the VM's connection to the rest of the network and shows a MAC address of `08:00:27:b2:40:4d` and an IP address `192.168.4.178`.  The `lo`, or loopback, interface is used for connections within the VM only and has the `127.0.0.1` IP address. 
>
>On the Windows VM I can find the same type of network configuration details by opening a command prompt and entering the `ipconfig` command.
>![[../images/03/activity_util_win_ipconfig.png|Windows IP Configuration|600]]
>The Windows VM shows the Ethernet interface with an IP address of `192.168.4.177`.  I could use the `/all` option with `ipconfig` to reveal more information about this interface; however, knowing the IP address is all I need for now.
>
>To demonstrate that the Kali and Windows VM can connect with each other, I can use a basic connectivity test using the `ping` utility that will send a message over the ICMP protocol.  From the Kali VM, I run `ping` with a count (`-c`) of four packets targeting the Windows IP address.
>![[../images/03/activity_util_kali_ping_fail.png|Failing to Ping Windows|600]]
>The result is 100% packet loss indicating that Kali was not able to reach the Windows VM or that the Windows VM ignored the ping requests.  By default, Windows blocks incoming ICMP requests through its native host firewall.  To allow the Windows VM to accept ping requests and to respond to them, I must enable the respective firewall rules within the Windows VM.  I do this by launching the "Windows Defender Firewall with Advanced Security" application and selecting "Inbound Rules".  In the main pane with all the rules listed, I find the "File and Printer Sharing (Echo Request - ICMPv4-In)" rules and activate each of them by right-clicking and selecting "Enable".
>![[../images/03/exercise_utilities_firewall.png|Windows Firewall ICMP Rules|600]]
>After the rules are enabled, I jump back to the Kali VM and rerun the `ping` command that failed.  This time all pings receive responses!
>![[../images/03/activity_util_kali_ping_success.png|Success Windows Ping From Kali|600]]
>Likewise, I can `ping` the Kali VM from the Windows VM using a simpler command without the count option since the Windows version defaults to four packets.
>![[../images/03/activity_util_win_ping.png|Windows Pings Kali|600]]
>Notice that each reply from the Kali VM has a *time to live (TTL)* of 64, whereas the reply from the Windows VM had a TTL of 128.  Linux machines usually respond with a TTL around 64 and Windows around 128, making the ping utility a useful resource to blindly identify operating system types across a network.
>
>The ability to trace the various devices that sit between your machine and a target can help to identify where a network connection may be failing.  For example, suppose my Kali VM could not connect to Google's website.  I could run a `traceroute` that may reveal where packets are failing to find Google's servers.
>![[../images/03/activity_util_kali_trace.png|Trace Route to Google|600]]
>This command tracing the route to Google succeeded and I can see that there were 14 devices, or hops, between my Kali VM and Google's web server.  The trace route utility sends an initial packet with a TTL of 1 and waits for the response back from the next node.  The node, which is my router in the above case, sees that the TTL has expired and responds to the request with its network information.  Trace route then increments the TTL by one, to two, and sends another request eventually reaching the next node behind the first identified node where the second node responds with its network information.  This continues until the destination is reached.
>
>Windows has a similar utility that can be used through the `tracert` command as demonstrated below.
>![[../images/03/activity_win_trace_complete.png|Windows Trace Route|600]]
>While we will cover DNS in the next chapter, it is important to know how to identify IP addresses from domain names.  Both Linux and Windows have an `nslookup` utility that will resolve the IP address for a given domain.  From the Kali VM, I can identify the Google domain's IP addresses by running the following command.
>![[../images/03/actvity_util_kali_nslookup.png|Google Domain IP Lookup|600]]
>I can see that `google.com` resolves to the IPv4 address `142.250.191.46` and that the DNS resolve is my home router at IP address `192.168.1.1`.  The last network utility I will cover here is `netstat` which can be used to identify a device's network connections and listening ports.  Within the Windows VM, I run the command with the `-aon` options to display all the listening and connected sockets, their process IDs (PID), address and port numbers.
>![[../images/03/activity_util_win_netstat.png|Windows Netstat Result|600]]
>The results include all the listening ports on the Windows VM such as 135, 445, and several others.  The netstat command is helpful when troubleshooting a client/server failure as the server must have a port open and listening on the interface to allow a connection to be made.  I can also see where this VM has established HTTPS connections with public IP addresses over port 443.  This can be helpful when inspecting a device's network behavior during malware analysis.
## Network Security
With the basics of networking now covered, we can begin to explore network security.  Network defenders must understand how computer networks function and the ways they can be attacked to ensure they stay secure.  Let's consider Cisco's definition of network security since they currently hold the largest market share of network equipment.

> [!quote] Network Security
*Network security is the protection of the underlying networking infrastructure from unauthorized access, misuse, or theft.*  -**Cisco Systems Inc**

Network security encompasses superior design and architecture of a network, use of security tools and hardware, as well as understanding the various attacks that can be waged on a network.  This section covers some of the basics to network security while the next chapter focuses on the security of network services.
### Risks
Network security risks coincide with the CIA Triad introduced in chapter one.  Networks are at risk of unauthorized access (confidentiality), modification of data (integrity), and denial of service (availability).  Consider the multiple ways an attacker could gain unauthorized access to a network.  A wireless network with a strong signal may allow an attacker access without being within the building.  Alternatively, an attacker could compromise an existing device within the network to gain a foothold.  Another brazen method of a network intrusion is using a *drop box*, such as a Raspberry Pi, that is physically installed within the network and connects back to the attacker for remote control.  Once inside a network, the attacker could intercept and inspect traffic that contains confidential data.  They could also modify that traffic to the benefit of the attacker such as changing account numbers on bank transactions.  Finally, the attacker could cause a *denial of service (DOS)* on network services blocking legitimate users access to the network.
### Network Segmentation
An effective way to limit exposures to internal networks is by separating a network into smaller networks called **network segmentation**.  This can be accomplished by using routers to define LANs.  For example, a router with four NICs where one of the NICS is used for a WAN connection and the other three are used for different LANs.  Managed routers and switches can support *virtual local area networks (VLANS)* which logically separate devices onto separate networks.  Consider the following network that is segmented into three separate networks.

![[../images/03/segmentation.png|Network Segmentation|450]]

The router or a firewall separates the traffic between the networks.  The router would block packets if a device in the office network attempted to make a connection to a device in the development network.  Packets could be allowed to travel between these networks if the router/firewall has a corresponding rule.  Secure networks apply a "deny all" rule that blocks all traffic to and from the network.  Network administrators then apply "allow" rules for specific and proven use cases, such as a development device needing access to an office printer.  Limiting access between networks ensures that if a network were compromised, the attacker would not be able to easily access other and possibly more critical networks.  For example, assume a development device is compromised due to a developer inadvertently installing a malicious plugin in their *integrated development environment (IDE)*.  This compromised device would not be able to connect to the office network where there could be sensitive customer data.

> [!tip] Tip - Separation of Concerns
> It is highly advisable to divide network resources into groups based on their threats and risks.  These groups should then be hosted within separate networks and maintain security controls commensurate with the level of risk.

A *demilitarized zone (DMZ)* is a common network architecture that separates internet facing servers from the rest of the network.  The internet is a hostile place, and new vulnerabilities are discovered all the time making internet facing servers easy targets to gain initial access on a target network.  Networks that are not separate are called *flat networks* and have a much higher risk of a complete compromise.  Once an attacker initially compromises a flat network, there is little in the way that blocks them because they can reach anything from anywhere inside the network.
### Firewall Stateless Inspection
Routers provide basic security rules that allow, or block traffic based on IP addresses and ports.  These simple rules provide reasonable security as they can prevent devices from reaching other devices on a network.  Another piece of networking equipment that offers the same security control and many more is called a **firewall**.  Know that there are other types of firewalls, such as a *host firewall* or a *web application firewall (WAF)*, but this section will focus on the *network firewall*, sometimes referred to as a *perimeter firewall*.  The network firewall is placed at the edge of the network, meaning that it sits between a modem and a router.  Network firewalls are basically routers with more security features.

The first-generation firewalls did not do much more than **stateless inspection**, where they analyze the header of packets to identify destination and source IP and ports against a set of rules to determine if the traffic was allowed to pass or should be blocked.  Each packet is inspected individually without consideration of packets before or after it.  This level of inspection is great for security, but a device intercepting all inbound and outbound network traffic also has more security inspection opportunities as will be covered in the next sections.
### Firewall Stateful Inspection
Second generation network firewalls consume more CPU and RAM resources but offer enhanced routing rules called **stateful inspection**.  These firewalls track streams of packets in their context within a table on the device.  With this collected data, the firewall can make rule-based decisions that consider established connections, sessions, services, or protocols.  Stateful firewalls inspect packet headers, payloads or data sections, and other fields.  They provide continuous monitoring and dynamic rules based on the state of the connection.
### Firewall Next Gen
Modern firewalls are called **next generation**, or **next gen**, and include the same network security features as previous generations plus several new ones.  Next gen firewalls terminate TLS encryption that decrypts traffic making it available to *deep packet inspection*.  Network or security administrators configure all devices to accept the firewall's TLS certificate, then the firewall intercepts all ingress (incoming) and egress (outgoing) TLS packets simultaneously decrypting and inspecting them for malicious content or other security violations.  Another security feature enjoyed by next gen firewalls is anti-malware, or antivirus, solutions, such as Palo Alto's *WildFire*.  Any files being downloaded or uploaded on the network will be scanned for malware.

Next gen firewalls integrate with identity providers, such as Active Directory, to provide *identity-based control*.  This allows the creation of firewall rules that consider the user principal in the decision logic.  Unlike first generation firewalls that could only consider an IP address and port number, next generation firewalls with identity-based controls consider the authenticated user when making allow or block decisions on network requests.  These firewalls can even identify the software being used to make requests and include them in the rule logic.  For instance, they can allow requests from a specific software access to a network resource and deny all others.

Next gen firewalls provide additional security protections using *intrusion detection and prevention systems (IDS/IPS)* that consist of rulesets for identifying malicious traffic patterns.  Researchers identify malicious patterns and create rules to detect them, which can be added to the IDS/IPS system.  These security systems support subscription to lists of known malicious IPs and domains that are used to block traffic.  Such lists are developed and maintained by community groups and professional commercial entities.  We will explore and configure IDS/IPS systems in greater detail in a future chapter.
### VPNs
Next gen firewalls also support *virtual private network (VPN)* services allowing clients to securely connect to a network from the internet.  Organizations often need to connect multiple geographically dispersed locations into a unified network providing seamless IT services to the user base.  Connecting geographically dispersed networks empowers users to share network resources like file systems, domain controllers, and printers.  VPNs fulfill this need through *site-to-site* connections where two or more networks are joined together using tunneling technology such as *generic routing encapsulation (GRE)* and encryption technology like *IPsec*.  GRE tunnels can be *split tunnel*, which carves or directs some traffic through the tunnel, or *full tunnel* which forces all traffic through the tunnel.  Together GRE and IPsec provide the ability to connect multiple networks while providing the network security needed over the hostile internet.

Another use case for VPNs by organizations is for a remote userbase that needs the same network services as those in a physical office.  For example, the remote user may need access to a file share that is only available on the company's internal network.  VPN technology allows secure access to network resources for remote users.  These remote access connections leverage VPN clients installed on the user's device while encrypting tunnels to networks using *transport layer security (TLS)*.  The VPN client creates a new *TUN* or *TAP* interface on the device depending on the network layer for which it is configured.  This interface is used to securely connect to the remote network

>[!information] Information - Consumer VPN Services
>Over the last several years there has been a huge rise in the consumer VPN space.  Customers of these services sign up for a low cost or free service to use with their personal devices.  While marketed as a security and privacy product, many consumer grade VPN services have questionable marketing and security practices.  Many consumers believe they are not secure unless they use a VPN; however, most websites are already encrypted using HTTPS.  Another common conception is that these services provide privacy; however, many of the service providers have been found to collect and sell customer data.
### Host and Service Discovery
Devices on a network must be able to identify and freely communicate with each other to ensure a normal and healthy network state.  They accomplish this through various network protocols and services which can be used to the advantage of network administrators and attackers to also discover devices on the network.  **Host discovery** is the process of identifying devices within a network using various methods.  Networks are usually very noisy with many devices frequently sending *broadcast* messages to all devices on the subnet.  Simply positioning a device on a network and listening for these broadcast messages, one could quickly discover many devices on the network.  Other devices can be identified across a network using utilities and protocols like ping and ICMP used earlier in this chapter.  Once a host is discovered, it can be scanned to identify the types of ports and services it offers.

Recall that TCP has a three-way handshake to establish connections with the ports of listening hosts.  This means that any device on the network can establish a layer three connection to any host with an open port.  Therefore, any device can test other devices on the network for any ports that might be opened.  Earlier in the chapter, we used the command line network utility `netstat` to identify open connections and listening ports from within a device.  These same ports can be identified by other devices on the network in a process called **port scanning**.

Once connected to a device's opened port, additional traffic can be exchanged that will indicate the type of service listening on that port.  Any response from a service could be used to identify the service on that port.  Sometimes this is as simple as the service advertising what it is and the version of software it is running.  Some services will advertise themselves once the requestor makes a connection to the open port, therefore avoiding the need for the requestor to guess the protocol needed to invoke a response from the service.  Other times the service can be derived by matching its behavior against a list of known patterns for common services.  For example, if you connect to port 80 and supply an HTTP request, the server might respond with a web page.  Ports and services do not have to follow normal configuration conventions.  For instance, an administrator can configure an HTTP service on port 22 which is usually used only for SSH.  Assuming that a service always uses its standard port number is not reliable.

> [!activity] Activity - NMAP
> There are several free and reputable tools that empower host and service discovery on the network.  The popular Netcat and NMAP tools work very well and are rich in features.  Many newer network tools, such as Masscan, have additional features and properties, such as being much faster!  Let's explore some of NMAP's host and service discovery capabilities.
> 
> In this activity I will configure both Kali and Windows VMs with the `Host-only Adapter` with the name `VirtualBox Host-Only Ethernet Adapter` network setting.  Before starting them, I will ensure they are on the same network and are disconnected from the internet.  The Windows VM's host firewall will be disabled which will expose all of its open ports to the network which will mimic a server on the network.  Once the machines and network are prepared, I will conduct a ping sweep from the Kali machine to discover the IP address of the Windows VM.  With this IP address in hand, I will run various host specific scans that identify more information about the Windows target.
> 
> First, I start the Windows VM with the `Host-only Adapter` network setting.  Once started and logged in, I launch `Windows Defender Firewall with Advanced Security` from the search bar.
> ![[../images/03/nmap_win_firewall_open.png|Launching Windows Defender Firewall|500]]
> With the Windows Defender Firewall with Advanced Security app launched, I press the "Windows Defender Firewall Properties" that is at the bottom of the Overview section in the main pane which launches the properties of the firewall.
> ![[../images/03/nmap_win_firewall_properties.png|Windows Defender Firewall Status|500]]
> The Windows host firewall has three sets of configurations, or *profiles*, depending on the type of network the machine resides.  The Domain profile is for Windows networks managed by a Domain Controller, the Private profile for trusted networks, and the Public profile for untrusted networks.  Each of the firewall profile configurations can be viewed using the respective tabs in the properties window.  As I want to demonstrate open network ports in this activity, I disable the firewall for each profile by selecting the "Firewall state" drop-down and choosing "Off" as shown in the following screenshot.  Then I'll press Ok to apply the settings.
> ![[../images/03/nmap_profile_off.png|Firewall Profile Setting Off|400]]
> With the firewall disabled, I launch a command prompt by entering `cmd` in the search bar.  I then identify the Windows VM IP address using `ipconfig` which is found to be 192.168.56.253.  We can derive that the CIDR range for the subnet is 192.168.56.0/24 from the Subnet Mask result of this command's output.
> ```
> ipconfig
> ```
> ![[../images/03/nmap_win_ip.png|Windows IP Address|600]]
> Now that the Windows VM victim is set up, I start the Kali VM using the `Host-only Adapter` with the name `VirtualBox Host-Only Ethernet Adapter` network setting.  This will ensure both VMs are on the same network and cannot inadvertently access the internet.  Once launched and logged in, I open a terminal by right clicking the desktop and selecting "Open Terminal Here" from the context menu.  I then type the `ip a` command to observe the IP address which is "192.168.56.252" and on the same "56" subnet as the victim machine.
> ```
> ip a
> ```
> ![[../images/03/nmap_kali_ip.png|Kali IP Address|600]]
> Now that the environment is set up, I can begin my reconnaissance from the Kali machine using NMAP, which comes pre-installed.  Running the following command with the help option lists all the available options and settings to configure scans.
> ![[../images/03/nmap_help.png|NMAP Help Options|600]]
> I will use the `-sn` option listed under the HOST DISCOVERY section in the help menu.  This option instructs NMAP to ping all IP addresses, whether there is a machine present or not, in each range and will inform me if any IP addresses respond.  I will also use the subnet identified on my Kali VM as an instruction in my NMAP command.  After a few moments, the results of the scan are returned that list the Kali and Windows VM IP addresses!  This is one way an attacker, or a network administrator, can identify hosts on a network.
> ![[../images/03/nmap_host_discovery.png|NMAP Host Discovery|600]]
> With the target IP address discovered, I can use NMAP to identify open TCP ports using the `-sT` option.  The following command specifies the target host instead of the CIDR range of the subnet.  NMAP will test 1000 common ports by sending TCP packets to each port and evaluate the response.  After running the command, I can observe a few open ports.
> ![[../images/03/nmap_tcp_scan.png|NMAP TCP Scan|600]]
> Sending TCP packets to every port can generate a lot of unnecessary network traffic and increase the chances of an attacker being discovered.  Alternatively, I could use the Netcat tool to evaluate specific ports of interest.  The Netcat tool's `-vz` options set a verbose output and zero input output mode which will identify if the port is open non-interactively.  I also specify the target IP address and port number in the command.  Observe that port 445 yields an open result though port 123 shows the connection is refused (closed).
> ![[../images/03/nmap_nc.png|Netcat Port Check|600]]
> I can use NMAP to target a specific port using the `-p` option.  This option accepts single, ranges, and lists of port numbers.  The results of the following command show the 445 port open and 123 port closed.
> ![[../images/03/nmap_port_specific.png|NMAP Port Specific Scan|600]]
> The NMAP tool can attempt to identify target operating systems and port services including versions by setting the `-sV` and `-O` options.  These settings require that NMAP run with elevated privileges, so I use the `sudo` command to run the scan.  Here, the output of the scan identifies our Windows 10 machine.  That is fairly good because it is not always that accurate!
> ![[../images/03/nmap_version_discovery.png|NMAP Version Discovery|600]]
> NMAP is a powerful tool, and I only demonstrated some of its basic uses. It can scan UDP ports and even run basic vulnerability scans.  It is extensible and you can write your own scanning scripts to discover even more!

## Wireless
The development of **Wi-Fi**, sometimes referred to as *Wireless Fidelity*, expanded networks beyond the confines of physical connection enabling networks to be formed over radio signals.  It is convenient for devices to connect to networks without Ethernet cables.  WIFI promotes the use of mobile devices and offers greater flexibility and communication within office environments.  For instance, companies use WIFI to enable operations and introduce mobile technologies like laptops, tables, and smart phones.
![[../images/03/wifi_network.png|Basic Wireless LAN Network|400]]

The IEEE 802.11 standards are the basis for **wireless LAN (WLAN)** networking that connects devices wirelessly to a *wireless router* or *access point*.  A wireless router establishes new networks and routes traffic without cables.  The access point has a wired connection to the network's switch and router and bridges the existing network.  These WLANs can be part of the existing LAN or create a new LAN depending on the configuration.  The figure above illustrates a simple network of wireless devices connected to a physical LAN through an access point.  

At the time of this writing, wireless network standards have been around several decades starting in the early 90s and have evolved over many versions, known as *generations*.  Each generation has some improvement over previous generations allowing for increased speeds or bandwidth using the 2.4, 5, or 6 GHz frequencies.  The greater the frequency, the more bandwidth capacity is available to the network.  You can think of frequency as the peaks and troughs of the signal.  The more tightly packed they are, faster data can be transmitted.  However, while higher frequencies are faster, they are also limited in their range as they have less physical object penetration ability.  Each generation is referred to by its IEEE standard with the latest 802.11 iteration *"be"*.  The table below from Wikipedia outlines all generations, their speeds, and radio frequencies. [^1]

![[../images/03/wifi_gens.png|WiFi Generations (source Wikipedia)|400]]

Wireless network names are known as **service set identifiers (SSID)** and are what you may be familiar with when connecting to a wireless network.  The SSID is the name that appears when a device scans the area for available networks to connect to.  A **basic service set identifier (BSSID)** is the MAC address of the wireless router or access point.  Some wireless networks can include multiple access points while being on the same network.  Each access point has to be distinguishable from one another using the BSSID. 

Wireless networks can be established under two service classes, **basic service set (BSS)** and **extended service set (ESS)**.  At its simplest, a peer-to-peer network could be formed by connecting two devices without a wireless router in an **independent BSS (IBSS)**.  Here, a network is formed by direct connections without a wireless router or access point while still forming an SSID.  For example, my consumer grade quadcopter drone connects with my smartphone using an IBSS.
![[../images/03/wifi_ibss.png|Independent Basic Service Set (IBSS)|200]]

Your home wireless network is likely an **infrastructure basic service set** where devices connect to a single wireless router that is connected to the physical network router.  In this service, the entire network creates a basic service set and the wireless router advertises its SSID with a unique BSSID.  
![[../images/03/wifi_infra_bss.png|Infrastructure Basic Service Set|250]]

Mentioned earlier, ESS networks have multiple wireless access points with unique BSSIDs and connect back to a single physical network router.  Collectively, this network forms an ESS under a single SSID where any device can connect to any BSS router and still be on the same network.

![[../images/03/wifi_ess.png|Extended Service Set (ESS)|250]]

ESS networks can usually be found in larger complexes where a single access point does not provide adequate coverage of the entire area needing wireless access to the network.  A common example is on a college campus where there is one WIFI or SSID used between buildings and students seamlessly connect between BSSs as they go between classes.
### Wi-Fi Security
The most obvious concern with wireless networks is unauthorized access.  Traditional physical networks mitigate the possibility of rogue devices accessing the network with physical security.  For example, due to physical security controls like armed guards, it would be difficult to get a physical device plugged into the network of my local FBI field office.  Network administrators rely on the fact that a malicious actor attempting to connect a physical device would have to bypass many physical security controls such as entering the premises, traversing walls, doors, receptions, and going unnoticed by employees.  It is conceivable that an individual could smuggle a device and connect it onto the physical network at demarcation points or within the office, but the physical security measures provide some control.  Most of these physical security controls are weakened with wireless networks as the radio frequencies they use leak outside the protected physical space.  Anyone can detect and capture wireless signals emitting from a building using high powered directional antennas.

Bypassing physical security controls through wireless technology was realized early in its development.  In response, several versions of security protocols that limit access to a wireless network and data have been implemented over time.  Early security standards were found to have critical weaknesses making them deprecated in favor of more modern and secure versions.  But each of the security standards share common characteristics of authentication and encryption to control access to a network.  A user must first authenticate onto the network and all radio transmissions carrying network packets are wrapped in a layer of encryption.  Strong passwords, secure encryption algorithms, and proper key handling become essential for the security of the network.  The following table summarizes the wireless encryption standards up to the current and recommended standard WPA3.

| Standard                        | Description                                                                                                                                                  | Security |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------- |
| Wired Equivalent Privacy (WEP)  | Original standard encrypting all data with a single short key.                                                                                               | Obsolete |
| Wi-Fi Protected Access (WPA)    | Replacement for WEP using temporal key integrity protocol (TKIP) which is now deprecated in favor of AES.                                                    | Poor     |
| Wi-Fi Protected Access 2 (WPA2) | Supersedes WPA offering pre-shared keys and advanced counter mode cipher block chaining message authentication code protocol (CCMP) chaining AES encryption. | Good     |
| Wi-Fi Protected Access 3 (WPA3) | Modern standard using enhanced cipher modes, secure handshakes, and brute force protections.                                                                 | Great    |

Other types of protections wireless network administrators can deploy include MAC filtering, tuning radio frequency power to limit the signal from leaking beyond the property and integrating wireless networks with intrusion detection systems (IDS) to detect and alert upon threats.
### Wi-Fi Attacks
The threat of a man in the middle (MitM) attack is prominent in a wireless network and is mostly mitigated through good encryption.  However, if the encryption is broken or implemented poorly, it opens the network to the attacker.  There are other techniques an attacker can use to intercept a victim's traffic.  A classic example of this is the **evil twin** attack in which the malicious actor sets up a wireless access point with a similarly named SSID to trick victims to connect to them.

![[../images/03/wifi_evil_twin.png|Evil Twin Attack|300]]

In the **evil twin attack** illustrated above, the attacker sets up a wireless router they control with a name like the existing network.  Notice the slight name change using the number zero in place of the letter "o".  The attacker could name the SSID something just as enticing like "FreeWi-Fi" and they may get connections in a crowded coffee shop.  If the attacker controls the router, they can decrypt any transmissions from victims and forward traffic to its intended destination while manipulating packets without the victim's knowledge.

Organizations must also concern themselves with **rogue access points** where an attacker, or an unwitting employee, connects a wireless router to the physical network.  Once connected to the physical network, the wireless router is given an IP address and devices can connect to the network wirelessly.

![[../images/03/wifi_rouge.png|Rogue Access Points|300]]

Not only can rogue access points cause network routing issues, but they extend the network beyond the confines of the physical network.  It can enable an attacker to reach the otherwise unreachable network providing remote access to wage additional attacks.  Good network security, like MAC filtering or port security, could prevent this attack.

Access to the wireless network can be jammed using radio emitting devices designed to cancel or disrupt the radio wave lengths preventing any user from connecting or maintaining connections.  Such jamming devices are available on Amazon for as little as $100.  Another wireless denial of service (DoS) attack is to simply boot a victim off the wireless network using the native *deauthentication (deauth)* request.  This **deauth attack** leverages the 802.11 standard to notify the access point that the device is disconnecting.  An attacker only needs be connected to the same wireless network and know the MAC address of the victim to repeatedly send deauth requests that boot the victim from the network.

![[../images/03/wifi_deauth.png|Deauth Attack on Wireless Network|400]]

Deauth attacks can be a component of other attacks where the malicious actor attempts to record a victim's key exchange with a wireless router.  The attacker will boot the victim off the network while having a wireless packet capture running.  When the victim attempts to reconnect to the wireless router, they must perform a key exchange to set up a secure connection.  The attacker collects the key exchange packets that can then be used to perform cryptanalysis or offline dictionary attacks.  This type of attack is what makes WPA insecure as the TKIP protocol is vulnerable to cracking.

![[../images/03/wifi_key_exchange.png|Wi-Fi Key Exchange Packet Capture|250]]

>[!activity] Activity 3.4 - WiFi WEP Cracking
>The wired equivalent privacy (WEP) standard is insecure as it repeats a short 24-bit initialization vector (IV) every 5k packets which is used to encrypt the traffic.  An attacker that captures several thousand packets has a high likelihood of cracking the encryption key used in WEP.  Once cracked, the key can be used to decrypt other packets that are captured allowing for the inspection and manipulation of WiFi traffic between the victim and the access point.  I'll demonstrate the security weakness of WEP using Aircrack to brute-force the IV from captured traffic.
>
>Capturing WiFi packets only requires a wireless NIC and for this demonstration I'll start by uploading the `kansascityWEP.pcap` (source accredited to edX) file to my Kali VM to simulate the output of the packet capturing process.  Kali already has the Aircrack tool installed which can be passed a PCAP file for the key brute forcing process.  After copying the PCAP to the VM's desktop, I open a terminal and begin the cracking process.
>```
>aircrack-ng ./Desktop/kansascityWEP.pcap
>```
>![[../images/03/activity_wep_aircrack.png|Cracking PCAP with Aircrack|600]]
>Aircrack analyzes the file and identifies the WiFi networks and their traffic statistics.  After just a moment, the tool cracks the WEP key and returns the hexadecimal value `1F:1F:1F:1F:1F`.
>![[../images/03/activity_wep_cracked.png|Cracked WEP Key|600]]
>With the key in hand, I open the PCAP within Wireshark by launching it through the Kali application menu.  Once launched, I navigate to the File menu, select the Open option, and choose the `kansascityWEP.pcap` file that was uploaded to the desktop.  The file has 802.11 protocol data encrypted, as illustrated below.
>![[../images/03/activity_wep_packets_enc.png|Encrypted WEP Packets]]
>To view the packets in a decrypted state, I must add the encryption key that was recovered using Aircrack.  To do this, I first enable the Wireless Toolbar that is under the View menu of Wireshark.
>![[../images/03/activity_wep_toolbar.png|Enable Wireless Toolbar in Wireshark|500]]
>Enabling the toolbar adds an additional row to our tool menu just above the packet listing pane in Wireshark.  To the right of the bar is a new button labeled `802.11 Preferences`.
>![[../images/03/activity_wep_pref.png|802.11 Preferences Button on Toolbar|600]]
>Pressing the button opens the Preferences menu and auto-navigates to the IEEE 802.11 settings.  To configure Wireshark with the WEP key, I select the `Enable decryption` checkbox and then press the Edit button next to the "Decryption keys" label.
>![[../images/03/activity_wep_enable.png|802.11 Settings|600]]
>After pressing the Edit button, the WEP and WPA Decryption Keys window pops up.  I press the `+` button to add a new key selecting WEP for key type and I enter `1F:1F:1F:1F:1F` for the key value.
>![[../images/03/activity_wep_key.png|Entering WEP Key Settings in Wireshark|500]]
>Once the key settings are in place, I press OK to close the WEP and WPA Decryption Keys window and then OK again to close the Preference window.  As soon as the Preference window is closed, Wireshark updates and decrypts all the packets.  I can now see each packet in plaintext which reveals several ARP packets!
>![[../images/03/activity_wep_decrypted.png|Decrypted WEP Packets|600]]

## Exercises

> [!exercise] Exercise 3.1 - Wireshark Packet Capture
> It is your turn to use Wireshark to capture and analyze packets on your Kali VM.
> #### Step 1 - Launch Wireshark
> With Kali running in Bridge Adapter network mode, login and launch a terminal.  Run the following command to start Wireshark.
> ```
> sudo wireshark
> ```
> #### Step 2 - Capture Packets
> With Wireshark launched, select the primary network interface (example eth0) and start a packet capture using the "blue fin" button in the upper left corner of the application.  Observe that packets start to collect in the main pane of the application.
> #### Step 3 - Analyze Traffic
> Launch a browser from the Kali VM while the Wireshark packet capture is running.  In the launched browser, navigate to the following URLs.  Note the protocol difference in the provided URLs.
> 
> `http://example.com`
> `https://example.com`
> 
> After loading each site, stop the packet capture, then find the related packets in Wireshark and view each stream using filters `http` and `tls` respectively.  To explore a stream, right-click the subject packet, select “Follow” in the context menu, and then select TCP/HTTP/TLS stream. 

>[!exercise] Exercise 3.2 - Network Utilities
>For this exercise you will use your Windows and your Kali VMs in the network Bridge Adapter mode.  Network modes can be set within the VirtualBox application by selecting the subject VM, choosing settings, then Network and finally selecting the mode from the "Attach to" drop down menu.  You will use Bridge mode to ensure each VM is on the same network and can communicate with each other.
>![[../images/03/virtualbox_network_example.png|VirtualBox VM Network Setting|500]]
>#### Step 1 - Check Network Configurations
 On your Kali VM, launch a terminal and run the following `ip` command to identify the IP address.
>```
>ip a
>```
>Similarly on your Windows VM, launch a command prompt and run the `ipconfig` command and identify the IP address.
>```
>ipconfig
>```
>#### Step 2 - Modify Windows Firewall
>Launch the “Windows Defender Firewall with Advanced Security” application and select “Inbound Rules”.  In the main pane with all rules listed, find the “File and Printer Sharing (Echo Request – ICMPv4-In)” rules.  Right-click the rule and “Enable” each of them.
>![[../images/03/exercise_utilities_firewall.png|Windows Firewall ICMP Rules]]
>#### Step 3 - Ping the VMs
>A basic connectivity test is to use the ICMP protocol to validate that packets can reach targets using the ping tool.  From the Kali VM’s terminal, ping the Windows VM using the following ping command with count (`-c`) of 4 packets.  Remember to replace `<WIN_IP>` with the IP address of the Windows VM.  If successful, you will see successful packet responses.
>```
>ping -c 4 <WIN_IP>
>```
>Likewise, ping the Kali VM from the Windows VM using the following command remembering to replace the `<KALI_IP>` with the IP address of the Kali VM.
>```
>ping <KALI_IP>
>```
>#### Step 4 - Trace the Routes
> From the Kali VM, trace the route to Google's webservers using the following command.
> ```
> traceroute goolge.com
> ```
>Similarly, trace the route from the Windows VM to Yahoo's web server.  Note the slight difference in the command between Linux and Windows.
>```
>tracert yahoo.com
>```
>#### Step 5 - Lookup IP Address
 From both the Windows and Kali VMs, lookup Google's IP address using the following `nslookup` (nameserver lookup) command.
> ```
> nslookup google.com
> ```
>#### Step 6 - Review Open Ports
>Discover what ports are open, listening services, and network connections made using the netstat command with `-aon` options ("a" for all, "o" for timers, and "n" for numeric).
>```
>netstat -aon
>```
>Identify any listening port on the Windows device and research that service.  Describe what that service is and how it is used.


> [!exercise] Exercise 3.3 - Host and Service Discovery
> Using your Kali VM's NMAP tool, you will discover the Windows VM on the network and scan it for open ports and services.  Before you begin, make sure each VM's network settings are set to `Host-only Adapter` to ensure they can reach each other on your virtual network.
> #### Step 1 - Disable Windows Firewall
> Within the Windows VM, open the “Windows Defender Firewall with Advanced Security” application, select “Windows Defender Firewall Properties” within the “Overview” section of the main pane.  For each ‘profile’ tab, set the firewall state to “Off”.
> #### Step 2 - Observe IP Addresses
> Check the IP addresses of the Kali and Windows VM for reference and ensure each has a unique IP address in each subnet. On the Windows VM, open a command prompt and run the following command.
> ```
> ipconfig
> ```
> Within the Kali terminal, run the following command.
> ```
> ip a
> ```
> #### Step 3 - Ping Sweep
> Discover the Windows VM from the Kali VM using NMAP’s ping sweep.  From the Kali terminal, run the following command. Make sure to replace `<IP/CIDR>` with the subnet CIDR notated IP range of your VirtualBox network (eg 192.168.40.0/24).
> ```
> nmap -sn <IP/CIDR>
> ```
> #### Step 4 - Port and Service Scan
> Scan the open ports and services of the IP address (Windows) discovered during the Ping Sweep. From the Kali terminal, run the following command. Make sure to replace `IP` with the IP address of the Windows VM. 
> ```
> nmap -sT -sV -p- IP
> ```


> [!exercise] Exercise 3.4 - WiFi WEP Cracking
> Using the Kali VM with any network setting, you will download the accompanying file `kansascityWEP.pcap`, crack its WEP key, and decrypt the traffic.
> #### Step 1 - Crack the PCAP
> Download the `kansascityWEP.pcap` to the desktop of the Kali VM.  Note that you should be able to drag and drop files from your host machine to the VM.  If not, consider revisiting the Lab 1 Workstation Setup instructions or seek alternative file transfer methods. 
> 
> Launch a terminal and crack the WEP encryption using aircrack-ng and observe the cracked encryption key.  Make sure the terminal is in the directory of the pcap file or provide a full path in the following command. 
> ```
> aircrack-ng kansascityWEP.pcap
> ```
> #### Step 2 - Decrypt Traffic
> After cracking the encryption key, launch Wireshark from the applications menu.  Do not start a capture.
> 
> Open the `kansascityWEP.pcap` file in Wireshark.  Select File -> Open and then navigate to the file.  Once opened, you should see encrypted 802.11 packets loaded.  Enable the Wireless Toolbar under the View menu. 
> 
> Press the “802.11 Preferences” on the right side of the Wireless toolbar. This will launch the Preferences window.  Ensure that “Enable Decryption” is selected and then press the “Edit” button next to the Decryption keys label.  Press the “+” button and add the decryption key value in the Key field.  Press Ok and return to the main Wireshark window.
> 
> You should now see all traffic decrypted (ARP packets).


[^1]:Wi-Fi Generations Table; Wikipedia 2024; https://en.wikipedia.org/wiki/IEEE_802.11