# Network Security
![](../images/03/globe_internet_connections.jpg)

Technologies that connect computer systems into groups or networks has increased the capabilities of systems and complexity by several orders of magnitude.  It has given rise to the internet and a countless ever expanding range of services.  Governments, organizations and individuals all rely on network systems to conduct a range of tasks that everyone depends on.  This level of complexity and dependency has given rise to many new account vectors for which we will focus on some of them in this chapter.  While it is assumed the reader knows some basic networking, we will revisit general networking technologies and concepts.  We will then introduce some of the technologies and practices used to secure networks.  In the later half of this chapter, we will analyze and exploit common networking technologies.  Not all network security concepts could be covered in one chapter, but the reader will become familiar with the basics of network security and at the same time learning how to approach other network related technologies and systems.

**Objectives**
1. To refresh knowledge on computer networking topics. 
2. Establish network security fundamental theory, threats, and approaches. 
3. Conduct host and service discovery through scanning utilities.
4. Analyze network packets using Wireshark.
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
There are several patterns or designs for connecting computers in a network, each with their benefits and disadvantages.  Network administrators determine what design to use when planning networks.  The following graphic illustrates the most common simplified patterns available.
![[../images/03/topologies.png|Network Topologies|600]]
The **peer to peer** network uses a *cross-over cable* that allows two computers to communicate directly with one another without the need of any networking equipment, such as a switch.  This simple design is elegant but not scalable.  When I was a pre-teen the PC game Doom had just come out and I have fond memories of my dad connecting his computer with my computer in the basement using a peer to peer connection and then playing deathmatches against each other - he didn't stand a chance.  Of course, this configuration is limited in that no other devices can be connected to the network.  You could however connect computers into a **ring** network where each computer connects to the next until a full circle is completed while using cross-over cables.  This method allows you to include more computers in a peer to peer like pattern but has the disadvantage of every device relaying every message and if scaled the network grows increasingly slower due to the number of hops to get from one computer to another.  A slightly better alternative is via the **bus** pattern where each computer in the network connects to a backbone, yet still it grows increasingly unstable with the addition to new devices and all devices could tap into the traffic of all other devices - less than ideal.  

Ring and bus designs require the transmission of data flow through several devices before reaching the final destination.  An adaptation to the ring topology called **mesh** allows each device to directly connect to every other device on the network.  While this potentially solves network delays and some security concerns from having to be routed through multiple computers, the number of connections grows substantially larger for every device added to the network.  Most networks nowadays follow a **tree** and a **star** pattern for network design.  The tree pattern is enabled through the use of network switches having a central point for network communications while providing the capabilities to expand the network by using multiple switches.  Similarly, the star pattern is often used by routers to connect multiple networks together.  Some of these designs are compatible with each other and can be used in conjunction to form a **hybrid** network.  For example, a star and tree network are often formed together into a larger network design.

### MAC Addresses
Every network interface card (NIC) has a unique address called a **media access control (MAC)**.  MAC addresses are assigned to the NIC during the manufacturing process and are meant to be unique and static (won't change).  Therefore, a MAC address is similar to your home address being unique and static while ensuring discoverability.  The address itself is composed of 6 octets commonly displayed in hexadecimal format.  As each octet is 8 bits the total number of bits in a MAC address is 48 or 6 bytes.  The first half of the MAC, the first 3 octets, is called the **organization unique identifier (OUI)** and identifies the manufacturer of the device.  For example, the OUI `FC:F8:AE` is one, of many, associated with the manufacturer Intel.  Therefore, if you know a devices MAC address you can ascertain information about the device type by looking up who the manufacturer is.  This can be useful information to network administrators, and attackers, when surveying devices connected to a network.  

The remaining bytes in the MAC address not associated with the OUI are a unique sequence meant to distinguish one NIC from another on the network.  As mentioned earlier MAC addresses are supposed to be static or never changing which avoids address collisions, or more than one device having the same address.  However, it is possible to change a NIC's assigned MAC address or convince other devices on the network that another device has a different MAC than the one assigned to it by the manufacturer which could subvert the normal operation of networks.  We will explore this concept further later in the chapter.

MAC addresses are used heavily in layer 2 (more on layers when we cover the OSI model) switches.  A network switch maintains a table of connected device MAC addresses so it knows which switch NIC to send traffic to.  MACs are also used in the *address resolution protocol (ARP)* which associates MAC addresses to *internet protocol (IP)* addresses.  ARP and IPs will be covered further in this chapter, just know that they use MAC addresses.
### IPv4
It wouldn't be feasible for network devices to maintain a list of all MAC addresses for all devices in all networks.  Therefore a grouping of networks and devices is needed to organize where traffic needs to be sent to.  The **internet protocol version 4 (IPv4)** specification enables the organization of networks through a 32 bit address, presented using decimal format, divided into a *network prefix* which identifies the network class, a *subnet* which identifies the network within the class, and a *host number* that specifies the device on that network.  IP addresses are then used to route traffic between networks and switches use them to associate them with MAC addresses and ensure traffic reaches their final destination on a network.  IP addresses are grouped together into classes as demonstrated in the following table.

| Class | Range |
| --- | --- |
| A | 0-127 |
| B | 128-191 |
| C | 192-223 |
| D | 224-239 |
| E | 240-255 |
IPv4 is presented in dot-decimal notation consisting of 4 octets.  Each octet goes up to the value 255 which is calculated by 2 to the 8th power (2^8) yielding 256, but since we start counting at 0 the highest number is 256.  The first octet defines which class the address belongs to and is managed by the *Internet Assigned Numbers Authority (IANA)*.  Several blocks of IP ranges are used for specific purposes and are handled appropriately by compliant network devices.  The rules that govern networking are cataloged in *request for proposals (RFC)* which detail specifications everyone must follow - some are better than others.  For example, and definitely worth committing to memory, RFC 1918 specifies which IP address ranges are designated for private networks - versus public networks.  Internet routers usually won't route private IP addresses as these addresses are used for every network and the probability of collisions is 100%.  Chances are, the LAN interface on your home router is 192.168.1.1, and so is mine.  It is therefore prudent we agree on which IP addresses are  public and which are private to ensure routing consistency on the internet.  The following table summarizes the RFC 1918 address space available to private networks.

| Start | End | Available Addresses |
| ---- | ---- | ---- |
| 10.0.0.0 | 10.255.255.255 | 16,777,216 |
| 172.16.0.0 | 172.31.255.255 | 1,058,576 |
| 192.168.0.0 | 192.168.255.255 | 65,536 |
The ability to see an address and instantly know if it is a public or private IP address makes a world of difference to network troubleshooting.

> [!note] Note - IPv6 
> While we won't be covering version 6, *IPv6*, it solves the same networking goals as IPv4 but provides several orders of magnitude address space.  It also has several features of networking streamlined and consolidated.  As of the writing of this text, IPv4 is much more popular in use, at least in the United States, so IPv4 remains the focus of this chapter.  However, IPv6 has its own security implications, while solving others, and is a great topic to review.
### Subnetting
As discussed earlier the IPv4 address space is divided into a prefix, subnet, and host.  The prefix will identify which class a network belongs to while the subnet will identify which network the IP address is associated with.  The final octet of the IP address is assigned to a specific host on that network.  Take the IP address `192.168.1.5` for example, the `192.168` prefix identifies this is a private IP address, the octet with `1` is the subnet and the octet with `5` is the host.  We can conclude that the host is in the `1` subnet of a private network.  Determining the subnet requires knowing the *subnet mask* which is advertised as part of network transmission.  Depending on configuration, some subnets are smaller or larger than a number in an octet - they divide a host range or span multiple decimals.  Most of the time a network engineer designs subnets in a manner that is easy to understand to avoid confusion resulting in dividing or expanding beyond a single octet or decimal.  Let's illustrate with some examples of potential subnet ranges:

| Start | End | Number of Hosts | Use |
| ---- | ---- | ---- | ---- |
| 192.168.1.0 | 192.168.255 | 256 | Most common because it is easy using 3 octet single value as the subnet.  The next network could be 2 then 3 and so on. |
| 192.168.1.0 | 192.168.1.4 | 4 | Used for subnetting WAN networks and VPNs. |
| 192.168.1.0 | 192.168.2.255 | 512 | Often used to accommodate a larger network |
Technically the number of hosts are 2 less than what is displayed in the table as the first and last address in a subnet are used for dedicated networking purposes.  Network administrators can divide the subnet space any way they need to in order to accommodate limited IP addresses and desired number of hosts within a network.  

You must be able to interpret networks while troubleshooting or evaluating network security.  Understanding what networks there are and where hosts are located is crucial in being able to connect to them, whether to secure them or to attack them.
### Classless Inter-domain Routing (CIDR)
Another useful skillset to have when interpreting networks is **classless inter-domain routing (CIDR)** notation.  IP address subnet ranges can be be notated with the format of prefix, forward slash, and then a number representing the number of bits.  For example, `192.168/16` represents the same as `192.168.0.0 - 192.168.255.255`.  The bit range, number after the forward slash, known as the *prefix*, represents the number of bits that comprise the prefix of the IP address.  The *host id*, is the number of bits that determine the number of hosts and is calculated by taking the total bit range, 32, minus the prefix.  Using the last example, calculating the host id is a matter of 32 minus the prefix `/16` which is 16.  To calculate the number of hosts you raise 2 to the power of the host ID value, 2^16 in using the previous example.  

Another common CIDR bit range is `/24`.  Applying the same math of 32 minus 24 to determine the host id results in 8; and 2 to the power of 8 is 256, the number of hosts in the range.  The following table itemizes some of the more common CIDR prefixes, host IDs, IP counts, and associated subnet masks.

| Prefix | Host ID | IP Count | Subnet Mask |
| ---- | ---- | ---- | ---- |
| /32 | 0 | - | 255.255.255.255 |
| /28 | 4 | 14 | 255.255.255.240 |
| /24 | 8 | 254 | 255.255.255.0 |
| /16 | 16 | 65,534 | 255.255.0.0 |
| /8 | 24 | 16,777,214 | 255.0.0.0 |
### Network Address Translation (NAT)
A router's WAN and LAN interfaces, or NICs, like any network interface, is assigned an IP address.  The IP address of the WAN interface, facing the internet, is provided a public IP address.  Your home router's WAN interface is assigned a public IP address which serves as the address for which internet resources can reach your network.  Similarly, LAN interfaces on a router are assigned an RFC 1918 private IP address.  This enables a network to have many devices while only requiring the network as a whole to have one public IP address.  Otherwise, every internet connected device would require a dedicated public IP address and we would have ran out of public IP address long ago as there are far more NICs then there are IP addresses.  This problem required that a solution that allowed multiple devices to have the same IP address and not have collisions, hence the creation of RFC 1918.  One of the router's jobs are to provide **network address translation (NAT)** where they track LAN address requests to public address space on the internet within a table.  When a LAN device requests a file from an internet address, the router logs this request in a table and when that internet address responds to the router, the router looks up which LAN address requested the internet resource and routes the inbound traffic to the appropriate private network.  The following diagram illustrates this setup with a private computer on the left within a network router that is internet connected.  
![[../images/03/nat.png|Network Address Translation|450]]
When the private computer at `192.168.1.5` reaches out to the internet resource at `49.123.1.5`, the request first reaches the router's LAN interface at `192.168.1.1` and then a record is logged in the router's NAT table.  The router strips the private computer's IP address from the request, replaces that IP address with its WAN address `116.45.12.99`, and it then forwards the traffic out to the internet.  The internet server at `49.123.1.5` will receive the request and then send a response to the router's WAN interface address at `116.45.12.99`.  The server does not know the private IP address of the computer because this detail was stripped off the request by the router.  The router then receives the server's response and looks up which LAN address made the request on the NAT table and then forwards the response back to that original requestor.  This architecture allows for many devices in a LAN to share a single public IP address assigned to the router's WAN interface - thus reducing the number of public IP addresses consumed and providing some anonymity for hosts making internet requests. 
### Ports, Protocols, Services
Networked devices communicate with each other via **protocols** which are predetermined rules of how and what can be communicated.  Protocols usually include what needs to be included in a communication, how they are initiated and end.  A protocol is much like how people interact with each other.  For example, a person initiating a phone conversation dials a number and waits for the other end to pick up.  The person receiving the call addresses the call with the greeting "hello".  Once the call is answered and greeted, the caller also states "hello" and then introduces themselves and explains why the are calling.  This is an example of protocol.  Similarly, it works this way between computers.  The exchange of information varies depending on the protocol.

When a computer engages another computer via network transmissions, it must first determine what computer is wants to engage with.  Ultimately the requesting computer identifies the IP address of the system it is targeting.  But IP address alone is not enough to establish a communication.  The requesting device must also identify which **port** to connect to. A port is represented by number 0-65535 with the port numbers 0-1023 being well known ports, numbers 1024-49151 are registered for specific purpose, and range 49152-65535 known as ephemeral ports.  These ephemeral ports are used by a requestor making an outbound connection so it can keep track of requests it makes and have an avenue to receive responses.  If an IP address is like the address to a house, ports are like the windows and doors of the house.  If a computer has an open port, it usually means it has a program running as a **service** that is configured to respond to connections to that port.  For example, port 80 is commonly used with the *hypertext transmission protocol (HTTP)* and a webserver listens for incoming connections to its port 80.  Ports could be open without a listening service and services can listen to closed ports - in either case communication over these ports fail.

> [!tip] Tip - Common Services and Ports
> There are many common ports and services a proficient security professional should know by heart.  For example, they should know what port is commonly associated with *file transfer protocol (FTP)* and which service is commonly associated with port 22.  Consider committing the following table to memory:
> 
> | Port | Service/Protocol | | Port | Service/Protocol |
> | --- | --- | --- | --- | --- |
> | 21 | File Transfer Protocol (FTP) | | 110 | Post Office Protocol (POP)
> | 22 | Secure Shell (SSH) | | 139 | NetBIOS |
> | 23 | Telnet | | 143 | Inter Message Access Protocol (IMAP) |
> | 25 | Simple Mail Transfer Protocol (SMTP)| | 443 | Hypertext Transfer Protocol Secure (HTTPS) |
> | 53 | Domain Name System (DNS) | | 3306 | MySQL |
> | 80 | Hypertext transfer Protocol (HTTP) | | 3389 | Remote Desktop Protocol (RDP) |
> | 88 | Kerberos | |5432 | PostgreSQL |

I rather like using a non-digital analogy to illustrate ports, protocols, and services in terms that anyone living in the United States can related to - the fast food drive through.  You enter the drive through and pull up to a speaker box (port) and patiently await an acknowledgment by the drive thru worker (service) from the sensors that detect a car has pulled up.  The worker greets you and you place your order (protocol).  After you have placed your order you pull up to the 1st window (port) and do not see anyone on the other side (no service!).  You wait a moment before realizing there is a second window and you decide to pull up to it.  Once stopped at the second window (port), another worker (service) greats you, collects payment, and delivers you your order (protocol).
### Transmission Control Protocol (TCP) and User Datagram Protocol (UDP)
The services, ports and protocols referenced in the last section are used higher on the network stack - more about this later in the chapter.  They depend on lower layer protocols to transmit requests between computers.  There are two core protocols in this transport layer, the **Transmission Control Protocol (TCP)** and the **User Datagram Protocol (UDP)** each with distinct benefits and disadvantages.

TCP uses a *three-way handshake* to establish connections between systems which verifies that the connection is made to both parties.  As illustrated in the figure below, the client initiates a request by sending a *synchronize (SYN)* request to the server.  Upon receiving the request the server responds with a *synchronize + acknowledge (SYN+ACK)* response back to the client.  The client receives the SYN+ACK and then sends an ACK packet to the server - thus finalizing the connection.
![[../images/03/three_way_handshake.png|TCP Three-Way Handshake|250]]
The handshake ensures both the client and the server have established the connection and then transmission of other requests and response can resume.  The downside to TCP is that it takes some time to make the round trip SYN, SYN+ACK, and ACK transmissions.  UDP on the other hand does not have this time delay as senders transmit *requests (REQ)* assuming the server receives them.  Servers may send a *response (RES)* made to them but the protocol is less dependable, although much faster than TCP.
![[../images/03/udp_req_res.png|UDP Request Response|250]]
### Open Systems Interconnection (OSI)
Each device on a network generally follows a model of how requests are generated, sent, received and interpreted.  The popular **Open Systems Interconnection (OSI)** model defines 7 layers used within a network device to explain how messages are handled.  Typically a message starts with a higher level protocol and is then passed to each consecutive lower layer before being converted to digital signals sent across an network wire.  Inversely, the receiver of the message first interacts with the message at the lowest layer and passes it up consecutively to the highest layer for interpretation.  The following table lists the 7 layers of the OSI model and corresponding protocols or network equipment.

| Layer Number | Layer Name | Protocol | Device |
| ---- | ---- | ---- | ---- |
| 7 | Application | HTTP, SMTP, DHCP, FTP, Telnet | - |
| 6 | Presentation | ASCII, TLS/SSL | - |
| 5 | Session | RPC, SQL, NFS, NetBIOS | - |
| 4 | Transport | TCP, UDP | - |
| 3 | Network | IP, ICMP, BGP, OSPF, IPSec | Router |
| 2 | Data Link | PPP, ARP | Switch |
| 1 | Physical | - | Ethernet Cable |

>[!info] Info - TCP/IP Model
>A now less popular, but original, network model **TCP/IP** follows a similar idea as the OSI model but has 4 layers grouping OSI's Application, Presentation, and Session layers into a single Application layer, and grouping Data Link and Physical layers into a Network Interface layer.  Reference to either model is correct, but its important to ensure they are used consistently to avoid needless confusion.
### Packets
The term **packet** is usually referred to as any message sent between computers or within any layer of the OSI model.  While convenient, it is technically untrue as some layers have different names for the messages.  Messages from higher layer protocols are referred to as *packet segments* that include a data section and usually a checksum to verify the message integrity.  These segments are passed to the network layer where they are wrapped with a header and footer detailing information about its source destination and port, thereon known as a *packet*.  The packet is sent further down the stack to the data link layer where the MAC address is added within another header known as a *frame*.  

Each layer has its own networking requirements that is uses to prepare or deliver a message.  The layer will add, or *wrap* or **encapsulate**, a message with data needed for that layer while it will strip, or **decapsulate** that same data as it passes the message received to a higher layer.  Messages that are too large to fit within one "packet" are broken up and sequentially labeled into what are called *packet fragments*.  These fragments are then reassembled into a complete message by the receiving device.  If any of the fragments become corrupt, validated using checksums, or go missing, from network errors, the receiving device can make a request for the missing packet from the sender.
### Analyzing Packets with Wireshark
Wireshark is a free tool that enables the user to capture and analyze packets on a device.  It is extremely useful when troubleshooting or exploring network communications as it collects and organizes all information from every packet.  It allows the user to identify the types of packets being sent and received, capture data on multiple OSI layers, and extract files that flowed through the NIC.  Features of the tool include filtering, statistical reports, encryption keys, and many more.

>[!activity] Activity - Wireshark
>Let's explore the Wireshark interface using the Kali VM.  To start Wireshark, I'll launch a terminal and enter the command `sudo wireshark`.
>![[../images/03/wireshark_start.png|Starting Wireshark]]
>To start capturing packets, select the Eth0 network interface and then the "blue fin" icon in the upper left corner of the screen.
>![[../images/03/wireshark_capture.png|Start Packet Capture]]
>Almost immediately we begin seeing packet entries in the top primary pane.  We can stop the capture at anytime by pressing the red square next to the capture button in the upper left corner.  The primary pane lists each captured packet in a table with the first column displaying the relative capture order, time, source IP or MAC, destination IP or MAC, the protocol and general packet info.  The bottom left pane displays a structured object of a selected packet and the bottom right pane shows the hexadecimal format of the packet.
>![[../images/03/wireshark_packets.png|Packets Captured]]
>I find that adding the source and destination ports as columns to the main pane is useful.  To alter the displayed columns, right-click the column header, select `Column Preferences` from the context menu.
>![[../images/03/wireshark_col_prefs.png|Wireshark Column Preferences|300]]
> With the column preferences opened, push the "+" add button at the bottom of the window and double click `Number`.  Select Destination Port from the drop down menu then double click the title of the added row and enter `DstPort`.  Repeat these steps and add another column for the Source Port.  Next, drag and drop the newly created columns next to their respective columns that hold the address space.  Your Preferences window should look like the one below once complete.  Press OK to complete the changes.
> ![[../images/03/wireshark_add_col.png|Wireshark Add Columns]]
> Observe that the main pane now shows the source and destination ports for each packet!  Next I'll open the web browser within the VM and navigate to `http://google.com`.  Afterwards I'll apply the `http` filter in Wireshark to only display HTTP packets that have been captured.
> ![[../images/03/wireshark_filter.png|Filtering HTTP Packets]]
> Wireshark can display domain names instead of the IP address which will help us identify which of these packets are related to the Google domain.  To enable this setting, go to Edit and Preferences to launch the preference window.  Then select `Name Resolution` from the left navigation menu and check the `Resolve network (IP) addresses` option.  Press OK to apply the setting.
> ![[../images/03/wireshark_resolve.png|Wireshark Name Resolution]]
> Notice that the many of the IP addresses displayed in the main pane now display domain names instead of IP addresses!  The first packets don't look related to Google.  Scrolling down reveals several Google related packets.  To open the *stream*, or related packets, select the first packet and right click to open the context menu.  Select `Follow` and then `HTTP Stream` to open the stream.
> ![[../images/03/wireshark_follow.png|Follow Stream Feature]]
> The stream window opens and displays the request (red text) and the response (blue text) and any subsequent related packets. 
> ![[../images/03/wireshark_stream.png|HTTP Stream]]
> I'll close the stream and delete the `http` filter then press enter to display all captured packets.  Another great feature of Wireshark is its statistics reporting.  These reports can be helpful to get a general idea of the types of packets that were capture and potentially identify any unusual protocols or connections that are made.  Select the `Statistics` menu and then choose `Conversations` to open the report.  Press the `Name Resolution` option on the left menu and then choose the `IPv4` tab.  Observe the statistics from our connection to google.com!
> ![[../images/03/wireshark_endpoints.png|Wireshark Statistics Endpoint Report]]
> There are many other useful features of Wireshark.  We will revisit the tool again later in the textbook in the Malware Analysis section where we will carve files from packet captures.
> 

> [!exercise] Exercise - Wireshark Packet Capture
> Its your turn to use Wireshark to capture and analyze packets on your Kali VM.
> #### Step 1 - Launch Wireshark
> With Kali running in Bridge Adapter network mode, login and launch a terminal.  Run the following command to start Wireshark.
> `sudo wireshark`
> #### Step 2 - Capture Packets
> With Wireshark launched, select the primary network interface (example eth0) and start a packet capture using the "blue fin" button in the upper left corner of the application.  Observe that packets start to collect in the main pane of the application.
> #### Step 3 - Analyze Traffic
> Launce a browser from the Kali VM while the Wireshark packet capture is running.  In the launched browser, navigate to the following URLs.  Note the protocol difference in the provided URLs.
> `http://example.com`
> `https://example.com`
> After loading each site, stop the packet capture.  Then, find the related packets in Wireshark and view each stream using filters `http` and `tls` respectively.  To explore a stream, right-click the subject packet, select “Follow” in the context menu, and then select TCP/HTTP/TLS stream. 
### Network Utilities
Troubleshooting network issues is a common task for many technology professionals.  These skills are beneficial to network administrators, developers, security professionals, and anyone in between.  Windows and Linux systems usually come pre-installed with several tools that are useful for identifying network configurations and assist in troubleshooting efforts.  These same tools can be used by attackers to explore the network of a compromised machine.  

>[!exercise] Exercise - Network Utilities
>For this exercise you will use your Windows and your Kali VMs in the network Bridge Adapter mode.  Network modes can be set within the VirtualBox application by selecting the subject VM, choosing settings, then Network and finally selecting the mode from the "Attach to" drop down menu.  We use Bridge mode to ensure each VM is on the same network and can communicate with each other.
>![[../images/03/virtualbox_network_example.png|VirtualBox VM Network Setting|500]]
>#### Step 1 - Check Network Configurations
>Identifying the network configurations of a system can help you identify the interfaces the device has, its MAC address, its IP address, and other useful network settings.  On you Kali device, launch a terminal and run the following ip utility with the a, for address, command.  
>`ip a`
>Similarly on your Windows VM, launch a command prompt and run the ipconfig command.
>`ipconfig`
>Observe each VMs IP address of the machine to be used in later steps for this exercise.
>#### Step 2 - Modify Windows Firewall
>Your Windows VM comes pre-installed and configured with a host based firewall that block ICMP packets.  Enable the allow rules within the firewall to permit receiving and responding to ICMP requests (pings).
>
>Launch the “Windows Defender Firewall with Advanced Security” application and select “Inbound Rules”.  In the main pane with all rules listed, find the “File and Printer Sharing (Echo Request – ICMPv4-In)” rules.  Right-click the rule and “Enable” each of them.
>![[../images/03/exercise_utilities_firewall.png|Windows Firewall ICMP Rules]]
>#### Step 3 - Ping the VMs
>A basic connectivity test is to use the ICMP protocol to validate packets can reach targets using the ping tool.  From the Kali VM’s terminal, ping the Windows VM using the following ping command with count (`-c`) of 4 packets.  Remember to replace `<WIN_IP>` with the IP address of the Windows VM.  If successful, you will see successful packet responses.
>`ping -c 4 <WIN_IP>`
>Likewise, ping the Kali VM from the Windows VM using the following command remembering to replace the `<KALI_IP>` with the IP address of the Kali VM.
>`ping <KALI_IP>`
>#### Step 4 - Trace the Routes
>Understanding where packets are being routed through can be helpful with identifying where network issues may reside.  The trace route utility sends a packet with a *time to live (TTL)* of 1, and then increments this for every additional request, to trick the last system in the chain of identifying where the packet expires.  From the Kali VM, trace the route to Google's webservers using the following command.
>`traceroute goolge.com`
>Similarly, trace the route from the Windows VM to Yahoo's web server.  Note the slight difference in the command between Linux and Windows.
>`tracert yahoo.com`
>#### Step 5 - Lookup IP Address
>While we will cover DNS in the next chapter, it is important to know how to identify IP addresses from domain names.  From both the Windows and Kali VMs, lookup Google's IP address using the following nslookup (nameserver lookup) command.
>`nslookup google.com`
>#### Step 6 - Review Open Ports
>Discover what ports are open, services listening, and network connections made using the netstat command with `-aon` options ("a" for all, "o" for timers, and "n" for numeric ).
>`netstat -aon`
>System administrators may want to know if the device is running any services to ensure they are protected.  Also, an attacker may want to know what potential vulnerable services are listening on a device in an attempt to exploit it.
## Network Security
The term security is often used by those who defend and by those who attack.  Depending on who you ask, you might get different answers when questioning what is network security.  Let's consider Cisco's definition of network security; after all, they currently hold the largest market share of network equipment.

> [!quote] Network Security
*Network security is the protection of the underlying networking infrastructure form unauthorized access, misuse, or theft.*  -**Cisco Systems Inc**

Network security certainly encompasses good design or architecture of a network, use of security tools and hardware, as well as understanding the various attacks that can be waged on a network.  This section covers some of the basics to network security while the next chapter focuses on the security of network services.
### Risks
The security risks related to networks fits well with the CIA Triad introduced in chapter 1.  Networks are at risk of unauthorized access (confidentiality), modification of data (integrity), and denial of service (availability).  Consider how an attacker may gain access to a network.  For example, many offices have WiFi for ease of portability.  If a signal is strong enough, an attacker may be able to gain access without having step foot into the building.  Alternatively, an attacker could compromise an existing device within the network gaining a foothold.  Another brazen method of a network intrusion is through the use of a *drop box*, such as a Raspberry Pi, that is physically installed within the network and phones home to the attacker for remote control.  Once inside a network the attacker could intercept and inspect traffic potentially revealing confidential data.  Another option is to modify that traffic to achieve some impact or gain further access to sensitive data.  A very common risk is *denial of service (DOS)* where the attacker attempts to block a service from being accessible to legitimate users. 
### Network Segmentation
A great way to limit exposures to internal networks is by separating a network into smaller networks called **network segmentation**.  This can be accomplished by using routers to define LANs - a router with 4 NICs one being used for WAN and the other three can be used for LANs can support at least two physically separate networks.  Networking equipment, managed routers and switches, can support *virtual local area networks (VLANS)* that are logically separate at layer 3 and 2 of the OSI model.  Consider the following figure to illustrate this setup.
![[../images/03/segmentation.png|Network Segmentation|450]]
The router, or a firewall, keeps traffic from any network separate.  If an office machine, middle network, attempted to make a connection to a development network machine, left network, the router would block the packets.  Unless of course the router has a rule that allows traffic from the network, or device, to access another LAN network or device.  This is a worthy effort for security to mitigate the impact of malicious activity spreading to other areas of the organization.  Assume a development network device is compromised, for example a developer could inadvertently install a malicious plugin for one of the apps they are building.  This compromised device wouldn't be able to immediately connect to the office network where there could be sensitive customer data.

> [!tip] Tip - Separation of Concerns
> It is highly advisable to determine the various levels of threats and impacts devices can have, as well as what they need access to, and then design a network to segment those concerns.

A *demilitarized zone (DMZ)* is a common network architecture that separates servers publicly facing the internet from the rest of the network.  The internet is a hostile place and new vulnerabilities are discovered all the time make public facing servers easy targets to access a network.  If these machines were not separate and connected to a network with many other different purpose and sensitive devices or data the impact could be needlessly high.  Networks that are not separate, *flat networks*, have a much higher risk of a complete compromise.
### Firewall Stateless Inspection
Routers can provide basic rules that allow or block traffic based on IP addresses and ports.  These simple rule provide reasonable security as they can prevent devices from reaching other devices on networks.  There exists another piece of networking equipment called a **firewall**.  Know that there are other types of firewalls, such as a *host firewall* or a *web application firewall (WAF)*, but let's focus on the *network firewall* sometimes referred to as a *perimeter firewall*.  The network firewall is placed at the edge of the network, meaning that it sits between a modem and a router.  Network firewalls are basically routers with more security features.  The first generation firewalls did not do much more than **stateless inspection** where they analyze the header of packets to identify destination and source IP and ports against a set of rules to determine if the traffic was allowed to pass or blocked.  Each packet is inspected individually without consideration of packets before or after it.  This level of inspection is great for security, but there is a lot more opportunity available to such a network device since it intercepts all packets coming into and out of the network.
### Firewall Stateful Inspection
Second generation network firewalls enhanced routing rules through more resources (CPU, RAM) being dedicated to the inspection effort.  These **stateful inspection** firewalls track all packets in context of the other packets it relates to in a table.  This way they can make decisions based on rules that consider established connections, sessions, and the service or protocol.  Stateful firewalls inspect not just the headers of packets but the payloads and other fields of the packets.  They provide a continuous review with dynamic rules based on the state of the connection.
### Firewall Next Gen
The most modern firewalls are called **next generation or next gen** and include the same network security features as previous generations but also include several more.  Next gen firewalls terminate TLS encryption, also called *deep packet inspection*, so they can examine the contents of encrypted packets.  Network or security administrators configure all devices to accept the firewall's TLS certificate, then the firewall intercepts all ingress (incoming) and egress (outgoing) TLS packets but decrypts and inspects them for malicious content or other security violations.  Another security feature enjoyed by next gen firewalls is anti-malware, or antivirus, solutions, such as Palo Alto's *WildFire*.  More on antivirus later in this book.

Some firewalls integrate with application and authentication, or *identity based control*, solutions so that they can apply rules on traffic by software or by principal.  These firewall rules can allow or block traffic by users and groups or by specific applications. 

Next gen firewalls provide additional security protections such as *intrusion detection and prevention systems (IDS/IPS)* integrating rules of traffic and packet patterns known to have been associated with malicious activity.  IDS/IPS systems can also be integrated with streams or feeds of known malicious IPs and domains and block traffic accordingly.  We will have a chance to explore IDS/IPS systems with better detail in a future chapter.
### VPNs
Next gen firewalls also support *virtual private network (VPN)* services as they act as a VPN provider allowing clients to connect to a network from the internet.  Over the last several years there has been a huge rise in the consumer VPN space where customers can sign up for a low cost, or "free", VPN service to use with home devices.  The value of such services is not of importance here while we consider the common VPN use case of organizations - which certainly would use the consumer grade and often questionable services.

Organizations often need to connect multiple geographically dispersed locations into a unified network providing seamless IT services to the userbase.  Empowering members of the organization to share network resources like file shares, domain controllers, and even printers.  VPNs fulfil this need through *site-to-site* VPN where two or more networks can be joined together using tunneling, *generic routing encapsulation (GRE)* and encryption technology, *IPsec*.  GRE tunnels can be *split tunnel*, which carves only some traffic through the tunnel, or *full tunnel* which forces all traffic through the tunnel.  Together GRE and IPsec provide the ability to connect the two, or more, networks into one while providing the network security needed over the hostile internet.  

Another use case for VPNs by organizations are for the userbase who may need remote access to the network so they can enjoy the same network services as those in a physical office.  The remote access connections usually leverage VPN clients installed on the user's device and establish encrypted tunnels to the network using TLS.  The client running on the user's device creates a virtual interface *TUN*, for IP layer 3 packets, or *TAP* for layer 2 ethernet frames.  
### Host and Service Discovery
Networks are usually very noisy with many devices sending *broadcast* messages to all devices on the subnet frequently.  Other devices can be identified across a network using the ping utility we used earlier in this chapter.  Network administrators need to verify devices are reachable from across the network and by nature a network device must be able to send and receive packets.  **Host discovery** is the process of identifying devices within a network using these and other methods.  Once a host is identified it can be further scanned to identify the types of services it offers.

Recall that TCP has a three way handshake to establish connections on ports of hosts with IP addresses.  Assuming a device is reachable over a network, that the routers and switches will route the traffic, means any device on that network can establish a network, layer 3, handshake connection.  Therefore, any device can test other devices on the network for any ports that might be opened.  Earlier in the chapter we used the command line network utility, netstat, to identify open connections and listening ports.  These same ports can be identified by other devices on the network in a process call **port scanning**.

Once a port is discovered as listening or *open* it may respond with some protocol or content.  This response could be used to identify the service that is listening to the port on the device across the network.  Sometimes this is as simple as the service advertising what is is, and even the version of software it is running.  Other times the service can be derived by matching its behavior against a list of known patterns for common services.

> [!activity] Activity - NMAP
> There are several free and reputable tools that empower host and service discovery on the network.  The long popular Netcat and NMAP tools work very well and are feature rich.  Many newer network tools, such as Masscan, can have additional features and properties, such as being much faster!  Let's explore some of NMAP's host and service discovery capabilities.
> 
> Configuring both Kali and Windows VMs with the `Host-only Adapter` network setting before starting them will ensure they are on the same network.  Then the Windows VM's host firewall will be disabled which will expose all of its open ports to the network - this will mimic a server on the network.  Once the machines and network are prepared a ping sweep from the Kali machine will be performed to discover the IP address of the Windows VM.  With this IP address in hand, various host specific scans will be ran that identify more information about the Windows target.
> 
> First, we start the Windows VM with the `Host-only Adpater` network setting.  Once started and logged in, I'll launch `Windows Defender Firewall` from the search bar.
> ![[../images/03/nmap_win_firewall_open.png|Launching Windows Defender Firewall|600]]
> With the Windows Defender Firewall with Advanced Security app launched, I press the "Windows Defender Firewall Properties" that is at the bottom of the Overview section in the main pane which launches the properties of the firewall.
> ![[../images/03/nmap_win_firewall_properties.png|Windows Defender Firewall Status|600]]The Windows host firewall has three sets of configurations, or *profiles*, depending on the type of network the machine is on.  The Domain profile is for Windows networks managed by a Domain Controller, the Private profile for trusted networks, and the Public profile for untrusted networks.  Each of the firewall profile configurations can be viewed using the respective tabs in the properties window.  As we want to demonstrate open network ports in this activity, I'll disable the firewall for each profile by selecting the "Firewall state" drop down and choosing "Off" as shown in the following screenshot.  Then I'll press Ok to apply the settings.
> ![[../images/03/nmap_profile_off.png|Firewall Profile Setting Off|400]]
> With the firewall disabled, I'll launch a command prompt by entering `cmd` in the search bar.  Within the command prompt I use the following command to identify the Windows VM IP address which is found to be 192.168.56.253.  We can derive that the CIDR range for the subnet is 192.168.56.0/24 from the Subnet Mask result of this command's output.
> `ipconfig`
> ![[../images/03/nmap_win_ip.png|Windows IP Address|600]]
> Now that the Windows VM, or the victim, is setup, I'll start the Kali VM using the `Host-only Adpater` network setting.  This will ensure both VMs are on the same network.  Once launched and logged in, I open a terminal by right-clicking the desktop and selecting "Open Terminal Here" from the context menu.  I then type the "ip" command to observe the IP address which is "192.168.56.252" and on the same "56" subnet as the victim machine.  
> `ip a`
> ![[../images/03/nmap_kali_ip.png|Kali IP Address|600]]
> NMAP come pre-installed on Kali Linux.  Running the following command with the help option lists all the available options and settings.
> `nmap --help`
> ![[../images/03/nmap_help.png|NMAP Help Options|600]]
> We will use the `-sn` option listed under the HOST DISCOVERY section in the help menu.  This option instructs NMAP to ping all IP addresses, whether there is a machine there or not, in a given range and will inform us if any IP addresses respond.  I'll also instruct NMAP to use the subnet observed in the earlier step.  After a few moments the results of the scan are returned that list the Kali and Windows VM IP addresses!  This is one way an attacker, or a network administrator, can identify hosts on a network.
> `namp -sn 192.168.56.0/24`
> ![[../images/03/nmap_host_discovery.png|NMAP Host Discovery|600]]
> With the target IP address discovered, we can use NMAP to identify open TCP ports using the `-sT` option.  The following command specifies the target host instead of the CIDR range of the subnet.  NMAP will test 1000 common ports by sending TCP packets to each port and evaluate the response.  After running the command, we can observe a few open ports.
> `nmap -sT 192.168.56.253`
> ![[../images/03/nmap_tcp_scan.png|NMAP TCP Scan|600]]
> Sending TCP packets to every port can generate a lot of unnecessary network traffic and increase the chances of an attacker being discovered.  Alternatively, we could use the Netcat tool to evaluate specific ports we may be interested in.  The Netcat tool's `-vz` options set a verbose output and zero input output mode which will identify if the port is open non-interactively.  I also specify the target IP address and port number in the command.  Observe that port 445 yields and open result whereas port 123 shows the connection is refused (closed).
> `nc -vz 192.168.56.253 445`
> `nc -vz 192.168.56.253 123`
> ![[../images/03/nmap_nc.png|Netcat Port Check|600]]
> I can use NMAP to target a specific port using the `-p` option.  This option accepts single, ranges, and lists of port numbers.  The results of the following command show our 445 port open and 123 port closed.
> `nmap -p 445,123 192.168.56.253`
> ![[../images/03/nmap_port_specific.png|NMAP Port Specific Scan|600]]
> The NMAP tool can attempt to identify target operating systems and port services including versions by setting the `-sV` and `-O` options.  These settings require that NMAP run with elevated privileges so I'll use the `sudu` command to run the scan.  Here the output of the scan identify our Windows 10 machine, that's pretty good because it is not always that accurate!
> `sudo nmap -sV -O -p 445 192.168.56.253`
> ![[../images/03/nmap_version_discovery.png|NMAP Version Discovery|600]]
> NMAP is a powerful tool and I only demonstrated some of its basic uses. It can scan UDP ports and even run basic vulnerability scans.  It is extensible and you could write your own scanning scripts to discover even more!


> [!exercise] Exercise - Host and Service Discovery
> Using your Kali VM you will use NMAP to identify the Windows VM on the network and scan it for open ports while identifying services.  Make sure each VM's network settings are set to `Host-only Adpater` to ensure they can reach each other on your virtual network.
> #### Step 1 - Disable Windows Firewall
> Within the Windows VM, open the “Windows Defender Firewall with Advanced Security” application, select “Windows Defender Firewall Properties” within the “Overview” section of the main pane.  For each ‘profile’ tab, set the firewall state to “Off”.
> #### Step 2 - Observe IP Addresses
> Check the IP addresses of the Kali and Windows VM for reference and ensure each has a unique IP address in each subnet. On the Windows VM, open a command prompt and run the following command.
> `ipconfig`
> Within the Kali terminal, run the following command.
> `ip a`
> #### Step 3 - Ping Sweep
> Discover the Windows VM from the Kali VM using NMAP’s ping sweep.  From the Kali terminal, run the following command. Make sure to replace `<IP/CIDR>` with the subnet CIDR notated IP range of your VirtualBox network (eg 192.168.40.0/24).
> `nmap -sn <IP/CIDR>`
> #### Step 4 - Port and Service Scan
> Scan the open ports and services of the IP address (Windows) discovered during the Ping Sweep. From the Kali terminal, run the following command. Make sure to replace `<IP>` with the IP address of the Windows VM. 
> `nmap -sT -sV -p- <IP>`
