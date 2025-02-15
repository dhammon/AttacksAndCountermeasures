# Chapter 4 - Network Services

![](../images/04/ethernet_shield.jpg)

There are many types of network technologies consisting of solutions, services, and protocols that are of security interest.  In this chapter, you will understand a handful of these technologies by learning how they work and their security implications.  We will explore how to secure them and the ways in which they can be attacked.  The goal of this chapter, like so many others in this textbook, is to construct a model when approaching technologies by first learning how they work and then how they can be broken.  This chapter will specifically cover address resolution protocol, dynamic host configuration protocol, domain naming system, and the transmission control protocol.  Each topic is mutually exclusive but follows the same layout of explaining the basics, attack vectors, and how to protect them.

**Objectives**
1. Understand common network protocols and technologies.
2. Explain basic defense for network technologies.
3. Conduct attacks against DNS, DHCP, ARP, and TCP.
## Address Resolution Protocol
The last chapter introduced IP and MAC addresses while describing how they are used in networks through layers 3 and 4 of the OSI model.  These addresses are critical for computer communications across networks using network equipment like NICs, switches, and routers.  As previously described, each NIC is given a MAC address burned in at the factory.  Good behaving networked devices keep their MAC address static, meaning they never change.  But these addresses do not scale well across the internet as they lack the organization the IP address system provides.  Therefore, the internet relies on IP addresses to route traffic to and from sources and destinations.  A solution is needed that can resolve or map IP addresses to MAC addresses and ensure packets traverse networks effectively.  This solution is called **address resolution protocol (ARP)** and enables computers and switches to send packets among each other.  Within the network, each device maintains a dynamic inventory of MAC addresses for IP address ranges.
### ARP Protocol
A group of computers connected to a LAN managed by a switch may communicate with each other over the network.  For example, a computer may need to send spooled print files to a networked printer to print documents.  In this example, the computer will have the IP address of the printer, but the switch requires the MAC address to forward requests to the printer.  The computer will send an **ARP request**, or *REQ*, packet through the switch to all devices on the network that includes their MAC address.  The REQ packet *broadcasts*, or asks all devices connected to the network, "Who has the IP address `xxx.xxx.xxx.xxx`?"  Each device on the network receives the request and the device with the corresponding IP address will prepare and transmit an **ARP response**, or *RES*.  This response declares "I have that IP address, my MAC address is `xx.xx.xx.xx.xx.xx`" and sends the message using the original requestor's MAC address.  If no device responds, the request will hit the gateway, and the address will not resolve.

![[../images/04/arp_protocol.png|ARP Requests and Responses|300]]

The diagram above demonstrates a functioning LAN with 3 devices requesting and responding through a network switch.  The request and response packets are common on a network and can be observed in packet captures, such as those from the last chapter's Wireshark exercise.

> [!note] Note - Broadcasting
> The act of sending a packet to all devices simultaneously on a LAN is known as a *broadcast*.  
### ARP Cache/Table
Network devices, such as computers and switches, catalog the results of ARP messages into an **ARP table**, also known as the **ARP cache**.  This table stores the relationship between IP and MAC addresses and is used for forwarding packets to the correct destination.  The protocol first checks if a MAC address is defined in the ARP table before broadcasting REQ packets to the LAN via the address `255.255.255.255`.  If the MAC address for an IP is already known, the device will not send a broadcast, and instead it will create packets destined to the known MAC address.  Each entry, or row, in the ARP table holds the IP address, MAC address, and the entry type which can be either *static* or *dynamic*.

Static entries are set manually by system or network administrators, whereas dynamic entries are set by the ARP protocol discovery efforts.  ARP table entries also include expiration times where the entry will no longer be considered valid and will eventually fall off the table.  The expirations help keep the table from growing too large, and therefore slower, as devices are added and removed from the network.  In addition, IP addresses can change frequently so there could be new IP addresses for existing MAC addresses in the table.  Entries also specify the network interface associated with each IP address to support devices with multiple interfaces.

> [!activity] Activity 4.1 - ARP
> Let's demonstrate how ARP works using our lab environment.  I'll start the Ubuntu VM in NAT mode so it has connection to the internet and install the network packet capturing tool `tcpdump` which works similarly to Wireshark, but is a command line tool.  Next, I'll restart the Ubuntu VM and then start the Windows VM, both in `Host Only Adapter` to ensure they can reach each other.  With the environment setup, I will run a packet capture on the Ubuntu VM and invoke ARP requests and responses from the Windows VM.
> 
> With the Ubuntu VM started in `NAT` network mode, I open a terminal and run the `apt` install command to install `net-tools` which includes `tcpdump`.  Note, it is good practice to first update your system before installing new tools.
> ```bash
> sudo apt update -y
> sudo apt install net-tools
> ```
> ![[../images/04/arp_nettools_install.png|Installing Net Tools|600]]
> I power off the Ubuntu VM after net-tools is installed.  I then start both Windows and Ubuntu VMs in `Host Only Adpater` network mode on the "VirtualBox Host-Only Ethernet Adapter" setting.  With the Windows VM started and logged in, I launch a command prompt and check the machine's IP address using ipconfig.
> ```bash
> ipconfig
> ```
> ![[../images/04/arp_win_ip.png|Windows IP Check|600]]
> Similarly, I log into the Ubuntu VM, start a terminal session, and check its IP address using the `ip` command.  I can see that the Ubuntu VM's IP address is assigned on the `enp0s3` interface which I'll need to know for later when I run `tcpdump`.
> ```bash
> ip a
> ```
> ![[../images/04/arp_ubuntu_ip.png|Ubuntu IP Check|600]]
> Both VMs are observed to be on the 192.168.56.0/24 subnet which means they should be able to communicate with each other.  Next, I check the ARP table on the Windows VM using the `arp` command to see what entries it currently has.  The `-a` option shows all entries.
> `arp -a`
> ![[../images/04/arp_win_table.png|ARP Table Entries|600]]
> While there are several entries, I do not see an entry for the Ubuntu IP address.  This means that the Windows VM has not made any recent connections to Ubuntu.  Jumping back onto the Ubuntu VM I start a packet capture using `tcpdump` while setting the interface using the `-i` option and only capturing ARP packets.  I also use the `-vv` for "very verbose" output to give me details on the captured packets.
> ```bash
> sudo tcpdump -i enp0s3 arp -vv
> ```
> ![[../images/04/arp_tcpdump_listen.png|Tcpdump Listening|600]]
> The `tcpdump` command remains idle waiting for incoming and outgoing packets.  I will run the `ping` utility on the Windows VM to initiate MAC resolution since the Windows VM does not yet have the Ubuntu VM in the ARP table.  Back on the Windows machine, I run the following `ping` targeting Ubuntu.
> `ping 192.168.56.251`
> ![[../images/04/arp_ping.png|Ping Ubuntu|600]]
> The `ping` was successful!  Now I recheck the Windows VM ARP table to see if an entry exists for the Ubuntu IP address using the `arp` command.
> ```bash
> arp -a
> ```
> ![[../images/04/arp_table_2.png|ARP Table Recheck|600]]
> As highlighted in the screenshot above, the table now has a record for the Ubuntu VM that includes its MAC address!  Finally, I review the packets capture on the Ubuntu VM's running `tcpdump`.
> ![[../images/04/arp_captured_packets.png|Tcpdump Captured ARP Packets|600]]
> The packet capture collected two ARP packets.  The first packet that is not highlighted in the screenshot displays the REQ from our Windows VM at 192.168.56.253.  The second packet which is highlighted in white, shows the Ubuntu RES packet including the Ubuntu MAC address 08:00:27:6d:b9:2e.
### MiTM ARP Attacks
Consider the implications of the ARP protocol as demonstrated in the last activity.  The packets captured using `tcpdump` displayed the request and the response in a healthy network.  But this is very trusting by nature as any device on the network receives the packets and can respond, even if they do not hold that IP address.  By default, there is not much stopping another device from claiming that they hold the IP address and responding with their own MAC address.  This could trick a victim into communicating with the wrong device! 

An unauthorized entity that intercepts network traffic, usually by proxying or funneling that traffic, is known as a **man in the middle (MitM)** attack.  This attack requires the threat actor to place themselves between two or more victims.  The threat actor then routes traffic between the victims.  The victims of this attack think they are communicating directly with their intended target, but all traffic is being sent to the attacker instead.  The attacker's device will receive the victim's traffic, inspect, or manipulate it, and forward it to the appropriate destination.  The receiver of the attacker proxy traffic responds to the request by sending traffic back to the attacker who can inspect or manipulate the data before relaying to the original victim. 

The ARP protocol can be abused by an attacker on a network by responding to a victim's ARP requests.  This attacker can poison the victim's ARP table by flooding the victim with ARP RES packets that claim the IP address the victim is looking for belongs to the attacker.

![[../images/04/mitm_arp.png|MitM ARP Poisoning|400]]

The figure above captures the poisoning of devices on a network by a malicious actor.  The victim sends request packets, and the attacker responds with poisoned packets claiming to be at the request IP addresses being requested.

>[!activity] Activity 4.2 - ARPSpoof
>Let's demonstrate the ARP poisoning and spoofing attack in our lab.  I use the Kali and Ubuntu VMs in a virtual network.  The Kali VM will poison the ARP table of the victim Ubuntu machine.  The traffic from Ubuntu will then be routed through the attacker Kali machine and available for inspection.
>
>I begin by creating a virtual NAT network in VirtualBox by going to Tools, Network Settings.
>![[../images/04/activity_arp_nat_network.png|VirtualBox Network Settings|600]]
>With the VirtualBox network settings opened, I select the "NAT Network tab" and press the "Create" button.  This will cause a new "NatNetwork" to be generated with the IPv4 subnet 10.0.2.0/24.
>![[../images/04/activity_arp_nat_created.png|VirtualBox NAT Network Creation|600]]
>I then set the Ubuntu and Kali VM's network settings to use the "NAT Network" adapter and specify the newly created "NatNetwork" before I start each VM.  This ensures both VMs are on the isolated virtual network we just created.
>![[../images/04/activity_arp_vm_network.png|Ubuntu VM Network Settings NatNetwork|450]]
>After launching the Ubuntu VM, I log in, start a terminal session, and run the `ip` command to observe the address 10.0.2.7 which is in our virtual NAT network subnet.
>```bash
>ip a
>```
> ![[../images/04/activity_arp_ubuntu_ip.png|Ubuntu VM IP Address|600]]
> Still on the Ubuntu machine, I run the `route` command to identify the default gateway 10.0.2.1 in the destination placeholder address 0.0.0.0.  Before running the command, I need to install `net-tools` if not already on the machine.  The following screenshot shows the result of this command in a table that is word wrapped, so I have highlighted the table entry.  This entry identifies the virtual switch at 10.0.2.1.  The `-n` option leaves the IP addresses shown instead of resolved domain names.
> ```bash
> sudo apt update -y
> sudo apt install net-tools
> route -n
> ```
> ![[../images/04/activity_arp_route.png|Ubuntu Default Gateway Route|600]]
> I start setting up the attack from the Kali box by opening a terminal and switching to the root user.  Many of the commands needed for this attack require elevated privileges within Kali so it will be easiest to perform all actions as the root user.  Then I install `dsniff` which includes several utilities, including `arpspoof`, that I use to launch the ARP poisoning attack.  As a reminder, it is always good practice to update the system prior to installing new software as it may require dependencies to be up to date.
> ```bash
> sudo su -
> apt update -y
> apt install dsniff -y
> ```
> ![[../images/04/activity_arp_dsniff_install.png|Kali Dsniff Installation|600]]
> Before I use the newly installed `arpspoof` utility in `dsniff`, I need to configure the Kali machine to forward IP packets.  This will ensure the victim's traffic reaches its desired destination and returns an expected result while helping the attack remain discrete.  I accomplish this task by setting the value "1" to the `ip_forward` setting under running processes.
> ```bash
> echo 1 > /proc/sys/net/ipv4/ip_forward
> ```
> ![[../images/04/activity_arp_ipforward.png|Kali IP Forwarding Setting|600]]
> Prior to using `arpspoof`, I will need to identify the network interfaces to be targeted.  A list of interfaces can be identified using the `ip` command.  Here, I can see the primary interface is "eth0" which has an IP address 10.0.2.15 from the NatNetwork.
> ```bash
> ip a
> ```
> ![[../images/04/activity_arp_kali_interfaces.png|Kali Network Interface List|600]]
> Using `arpspoof`, I will tell the victim that the Kali address is the default gateway using the interface, victim IP, and gateway as options in the command.  The interface is configured using the `-i` option while the target is defined under the `-t` option.  Once entered, the tool immediately begins flooding the victim with ARP RES packets claiming the Kali VM's IP on interface eth0 is the gateway.  Eventually, the victim will add these claims in the ARP table and start sending traffic to Kali instead of the gateway.  Recall that we learned about the Ubuntu IP address and the gateway from the commands ran on the Ubuntu machine, but they could have been discovered through network reconnaissance efforts, like using NMAP.
> ```bash
> arpspoof -i eth0 -t 10.0.2.7 10.0.2.1
> ```
> ![[../images/04/activity_arp_poison_victim.png|Kali ARP Poisoning Victim|600]]
> With the ARP poisoning running against the victim Ubuntu machine, I set up another `arpspoof` targeting the default gateway.  The purpose here is to poison the gateway into thinking that the Kali machine is the Ubuntu victim machine.  The command is like the previous one, except the IP address for the victim and the gateway are in swapped positions.  I open another terminal and switch the user to root then run `arpspoof` again.
> ```bash
> sudo su -
> arpspoof -i eth0 -t 10.0.2.1 10.0.2.7
> ```
> ![[../images/04/activity_arp_poison_gateway.png|Kali ARP Poisoning Gateway|600]]
> Kali now has two open terminals each running `arpspoof` trying to poison the ARP tables of the gateway and the victim.  Once they are both adequately poisoned, they will send traffic to the Kali machine and Kali will forward the packets to the intended destination.  At this point, I can observe the intercepted traffic using a `tcpdump` packet capture.  I configure `tcpdump` to use the default snapshot length by using the `-s 0` option and filter the traffic to include http traffic only.  I also use the `-vvv` for "very very verbose" output.  `Tcpdump` will be ran within a fresh terminal, the third terminal instance, in the Kali machine as root.
> ```bash
> sudo su -
> tcpdump -i eth0 -s 0 'tcp port http' -vvv
> ```
> ![[../images/04/activity_arp_capture.png|Kali Tcpdump HTTP Packet Capture|600]]
> Any HTTP packets from the victim should now appear in my `tcpdump` packet capture running in Kali.  I can now demonstrate packet sniffing by invoking an HTTP request from the victim Ubuntu machine.  Switching back to the Ubuntu machine, I make a HTTP request to "example.com" with password as a GET parameter by using the `wget` utility.  I also output the text to a temporary test file.
> ```bash
> wget http://www.example.com/?password=SuperSecret -O /tmp/test
> ```
> ![[../images/04/activity_victim_http_req.png|Ubuntu HTTP Request|600]]
> I can see that the request to "example.com" succeeded without any noticeable delay or issue while on the Ubuntu VM.  Jumping back to the Kali machine, I can see HTTP traffic was captured in the `tcpdump` output.  Scrolling up through the logs, I see both the request and the response from "example.com", which includes the victim's password in the GET request!
> ![[../images/04/activity_arp_password_captured.png|Kali Captured HTTP Packets|600]]
### Securing ARP
The ARP protocol is very permissive, as demonstrated in the previous pages.  There are several controls that can be applied to help mitigate the risks imposed by ARP.  Higher layer traffic, such as HTTP in layer 7, can use encryption technologies like TLS to encrypt packet data fields.  Using encryption ensures that packets intercepted by an attacker are not readable, at least not without additional effort on the attacker's behalf.  It is conceivable that an attacker could intercept key exchanges, or even mock a key exchange, tricking the user to use the attacker's encryption keys. 

Because the ARP spoof attack relies on the use of dynamic entries in the ARP table, a network administrator could use static entries preventing attacker hijacking.  This will prevent the attacker from poisoning the ARP table and launching an effective man in the middle (MitM) attack.  However, it is not always feasible for an administrator to manage static entries as networks can grow large, complex, and be very dynamic.  For larger networks in which static assignments are not feasible, administrators should use *dynamic ARP inspection (DAI)* that leverages the *DHCP snooping* table on a network switch to inspect ARP packets against the known good MAC and IP associated entries.  Any packets that violate DAI will be dropped and prevent an attacker from succeeding in an ARP poisoning attempt.  We will explore DHCP snooping security and DAI in more detail in the DHCP section of this chapter. 

Another mitigation strategy is to use a segmented network design in which networks are broken up into smaller networks separated by a physical or virtual router.  The ARP spoofing attack is only effective against devices within a LAN, and by separating devices into smaller LANs, the impact of the attack can be limited to a smaller network.
## Domain Name System
Networked devices reach other networked devices through IP addresses.  These addresses enable traffic to reach their ultimate destinations through layer 4 routers.  IP addresses work well for computer systems but are not ideal for human use as they do not convey meaning or context very well.  For example, when needing to search for something on the internet, it is more convenient for a user to remember and navigate to "google.com" instead of "142.250.189.238".  The system that enables the use of names instead of IP addresses is called **domain name system (DNS)**.  This system is supported by various servers on the internet and within LANs that resolve domain names to IP addresses.  A user can enter a domain name and the IP address is looked up and then used to reach its ultimate destination.

![[../images/04/dns_resolution.png|DNS Resolution of Google|300]]

### DNS Infrastructure
DNS services use UDP port 53 for domain name resolutions and TCP port 53 for zone transfers.  When a client, such as a browser, requests an IP address of a domain, it first looks locally within the *host file* for any overriding entries.  If no entries are found in the hosts file that match the request, the client then requests resolution via port 53 to the *DNS resolver*, which is a server that stores a cache of domain to IP address *bindings* or mappings.  The DNS resolver is often included within many home or small office network routers, but it can also be a standalone server dedicated to DNS resolutions.  Regardless, if the resolver does not have an accompanying entry, it will reach out to the *top level domain (TLD) nameserver* identified by the *root server*.  Root servers administer domains under the last section of the URL, such as ".com".  The TLD server will identify the *authoritative server* that holds the IP address record to make the final requests.  The authoritative server is the source of truth for the IP to domain binding and responds with the IP address for the domain back to the client.  With the IP address now known, the client can make the request to the respective server.

![[../images/04/dns_infra.png|DNS Infrastructure Flow|400]]

The image above demonstrates the flow of a DNS resolution.  Each server will store, or *cache*, the result of DNS records in its records for faster response times.  The propagation of these records can take some time and may also depend on the record's expiration, known as the *time to live (TTL)*.
### DNS Records
A DNS authoritative server holds various entries or **DNS records**, that map the relationships between IP addresses and domain names.  The following table outlines some of the most common DNS records.

| Record Name | Description                                                           |
| ----------- | --------------------------------------------------------------------- |
| A           | Apex record that holds the IPv4 address for a domain                  |
| AAAA        | Holds the IPv6 address for a domain                                   |
| CNAME       | Conical name, or Alias name, for a domain and subdomains              |
| MX          | Mail exchange that directs emails to email servers                    |
| TXT         | Text record often used to verify domain ownership                     |
| NS          | Nameserver records                                                    |
| SOA         | Start of authority containing admin information                       |
| SRV         | Service port                                                          |
| PTR         | Pointer record providing reverse lookups of domains for an IP address |

Network administrators create these records depending on the needs of the network.  It is common to see the "A" record as it provides the IP address for the given domain name.  Sometimes other domains can point to the same IP address causing the need for an alias or CNAME record.  This record can also be used when a domain has one or more subdomains that point to other IP addresses.  A common subdomain is "www" but a domain may have any compliant value as a subdomain, or even nested subdomains underneath an existing subdomain.
### Zone Transfer
While DNS servers face the internet and serve anonymous queries, DNS records are typically not advertised.  For example, you cannot go to Google's authoritative server and download all DNS records that include all the CNAME and MX records.  These records are not secrets but advertising them unnecessarily exposes details of the domain making it easier for malicious actors to identify targets in the domain.  However, because records are public, there is nothing stopping anyone from aggregating this information centrally and providing a lookup service, such as on "dnsdumpster.com". 

Relying on a single authoritative server could impose availability risks with a domain.  For instance, when the server needs updates, it will temporarily go offline resulting in downtime for a domain or website.  Therefore, most administrators will ensure that they have at least one other authoritative server to maximize the availability of their domain in the DNS system.  Keeping both servers synchronized with the same records then becomes a chore as the administrators must update both servers every time there is an update to the DNS record set.  If the administrators managed a fleet of DNS servers, there is a greater chance of missing an update on a server and could cause clients to intermittently fail DNS resolutions.  Therefore, many administrators will establish some form of automation by leveraging **zone transfers**.  These zone transfers enable the synchronization, or copying, of domain zones along with all DNS records between authoritative server clusters.  However, as mentioned earlier in this section, an administrator would want to avoid exposing the zone transfer service to unauthorized users by ensuring that access to TCP port 53 DNS service is restricted.

>[!activity] Activity 4.3 - Zone File
>Let's demonstrate some of what we have learned so far on DNS records and zone transfers.  I use "dnsdumpster.com" to investigate Google's domain and see which records have been publicly collected.  Then I attempt a zone transfer of Google's domain before demonstrating a live zone transfer on a vulnerable by design domain.
>
>Using the Ubuntu VM with `NAT` network mode set to ensure access to the internet, I open the default browser Firefox and navigate to "dnsdumpster.com".  Once at the site, I enter `google.com` into the domain and review the results.
>![[../images/04/dnsdumpster.png|DNS Dumpster Google Domain Results Overview|600]]
>The site displays geographic pins where the Google servers are located.  Scrolling down the page shows NS, MX, and TXT records that have been cataloged.
>![[../images/04/dnsdumpster_records.png|DNS Dumpster Google Records]]
>Several subdomain records are itemized on the page.  Other "A" records can sometimes be found by pressing the grid icon under the domain record on the list.
>![[../images/04/dnsdumpster_host.png|DNS Dumpster Google Host Records]]
>This passive review of a domain is useful, however incomplete. Only discovered records are listed and some of them might no longer be valid.  To collect the entire record set of a zone, I can use the `dig` utility.  I open a terminal on the Ubuntu VM and look up the nameservers of google.com.  With the nameservers identified, I use the `dig` command with the `axfr` settings to request a zone transfer for "google.com" from one of its nameservers.
>```bash
>dig +short NS google.com
>dig axfr google.com @ns3.google.com
>```
>![[../images/04/dig_google.png|Attempted Google Zone Transfer With Dig|600]]
>Unfortunately, the transfer failed, likely because the Ubuntu VM's public IP address is excluded from Google's allow list.  To demonstrate what a zone transfer looks like, I can use the "zonetransfer.me" domain using the same commands.
>```bash
>dig +short NS zonetransfer.me
>dig axfr zonetransfer.me @nsztm1.digi.ninja
>```
>![[../images/04/zone_transfer_me.png|Successful Zone Transfer|600]]
>The zone transfer succeeded and displayed all the records of the domain!  This could be useful information for an attacker while performing reconnaissance looking for weak targets.
### DNS Threats
There are at least a few threats that must be considered when designing a secure DNS system.  Should the system become unavailable, it could result in clients not being able to resolve the domain names needed to access an organization's internet services.  A *denial of service (DoS)* attack in which an attacker causes the DNS servers to be offline, is an example of such a risk.  One option to mitigate DNS DOS attacks is by using an upstream network performance provider such as NetScout.  This mitigates the risk by requiring DNS queries to be passed through proxies that inspect traffic and discard malicious requests before reaching authoritative servers.   

Another risk to DNS systems is the takeover of the domain.  A takeover can be caused by a lapse in the upkeep of the domain registration or through a *registrar* account compromise.  For instance, accounts on a registrar like GoDaddy can be compromised if an attacker obtains the login credentials for a domain.  To mitigate the chances of an account compromise, administrators should ensure their registrar contact details are up to date, multifactor authentication is enabled, and strong unique passwords are used.  An interested, or malicious, third party could procure the domain and takeover any new records.  They could also steal credentials to the login system for the registrar and expel other administrators from accessing the registrar's web console.   

Yet another risk to DNS is through attacks on the protocol itself in which a malicious actor convinces networked devices that they are the DNS server (root, authority, or resolver).  Under such a threat, the attacker can replace domain queries with malformed results and hijack client requests.  This risk can be mitigated by using *DNSSEC*, which authenticates and validates resolver responses to domain queries within a network. 

A **local cache poisoning** attack, in which the attacker poisons or spoofs DNS responses through the local hosts file, can cause victims to receive malicious DNS responses hijacking their flow of traffic.  In this scenario, the victim requests a domain and receives an IP address that is in the control of the attacker.  The attacker can then more easily trick users with phishing sites that can be used to harvest the victim's credentials.

![[../images/04/local_cache_poisoning.png|Local Cache Poisoning|200]]

This poisoning attack can be illustrated by modifying the DNS Infrastructure diagram shared in the earlier part of this chapter.  The image above demonstrates the local cache poisoning attack wherein the attacker sets the domain to an IP binding in the hosts file which directs the victim to an attacker-controlled server.  The DNS resolver could also be compromised in a **remote cache poisoning** attack.  Here, the attacker has the same objective of replacing domain to IP bindings with malicious IPs.   

Borrowing again from the DNS Infrastructure diagram, the image below illustrates an attacker compromising the DNS resolver and polluting the DNS response.

![[../images/04/remote_cache_poisoning.png|Remote Cache Poisoning|375]]

A **malicious DNS server** is yet another attack in which the threat actor seeks to hijack the DNS response with a malicious one.  In this attack, the adversary sets up their own DNS resolver on the network and influences hosts to use it over the real resolver.  This has the same impact as the remote cache poisoning attack but avoids the need of compromising the real resolver.  The diagram below shows the malicious DNS server sitting on a network and responding to client requests.  

![[../images/04/malicious_dns_server.png|Malicious DNS Server|375]]

An attacker may also attack DNS servers directly through a **DNS flood attack** to cause the server to fail its responses to client requests.  This is a type of denial-of-service (DoS) attack which disrupts the normal operation of DNS services.  Under resourced servers or servers that have a vulnerability that exposes the DNS service can be susceptible to DoS attacks.  The attacker could also use several devices or a *bot army* to send the many requests at once and overwhelm a targeted DNS server.  The diagram below demonstrates this attack blocking the client from using the resolver.

![[../images/04/dns_flood_attack.png|DNS Flood Attack|350]]

Firewalls can limit outbound port or application connections to the internet for some networks.  Good security posture ensures that only authorized traffic is permitted to leave the network, such as limiting outbound traffic to HTTP.  Another service commonly allowed to egress a secure network is DNS over UDP port 53.  An attacker needing to exfiltrate data, such as file transfer, will not be able to move files out of the network using a protocol like file transfer protocol (FTP); however, an attacker could abuse the DNS service to exfiltrate data.  Even if an attacker could move files over some file transfer protocol, they may choose not to so it can evade detection as DNS traffic is usually not heavily monitored.   

To accomplish **DNS tunneling exfiltration**, an attacker segments a file into small clips and then encodes them into an HTTP compliant character set (a-z0-9-.).  Each segment is then used as the subdomain of an attacker control domain and resolver.  The victim's resolver will not recognize the subdomain and will initiate a request to the attacker's authoritative server.  The attacker controlled authoritative server logs are then compiled and reassemble the decoded subdomains back into the original file!  This technique is useful to attackers that have compromised a network and want to exfiltrate data discreetly.

>[!activity] Activity 4.4 - DNS Spoofing
>I will demonstrate a DNS spoofing attack using the three VMs, Kali, Ubuntu, and Windows on `Bridge Adapter` network settings.  The Kali VM will serve as the attacker, the Ubuntu machine will be set up as a DNS resolver using `dnsspoof`, and the Windows VM will be our victim.
>
>Starting with the Ubuntu machine, I install `dsniff` after I update the system.
>```bash
>sudo apt update -y
>sudo apt install dsniff -y
>```
>![[../images/04/dns_spoof_ubuntu_dsniff.png|Ubuntu Installing Dsniff|600]]
>My DNS server will be set up to only resolve www.google.com, but I first need to know Google's IP address.  I use `nslookup` to find Google's IP address and then create a domain to IP binding in a `dns.txt` file.
>```bash
>nslookup www.google.com
>echo "142.250.189.164 www.google.com" > dns.txt
>```
>![[../images/04/dns_spoof_dnstxt.png|Setting Up DNS Record|600]]
>Using the `ip` command, I identify the interface that the DNS server will run on.  Then, I start `dnsspoof` to serve the `dns.txt` records on that interface.  `Dnsspoof` is not a reliable DNS server application and is only being used here as it is easier than setting up a real DNS server.
>```bash
>ip a
>sudo dnsspoof -i enp0s3 -f dns.txt
>```
>![[../images/04/dns_spoof_dns_server.png|DNS Server Running on Ubuntu|600]]
>With the DNS server running and ready to resolve web.google.com, I switch to the Windows VM and configure the DNS resolver setting with the Ubuntu IP address.  I search for "View network connections" in the search bar and open the Control panel.
>
>![[../images/04/activity_dnsspoof_control.png|Opening Network Connections|600]]
>The "Network Connections" window is opened and displays the network interfaces.  I right-click the Ethernet entry and select "Properties" from the context menu options.
>![[../images/04/dns_spoof_ethernet_properties.png|Ethernet Properties|350]]
>Within the Ethernet Properties window, I select the "Internet Protocol Version 4" option and press the "Properties" button.
>![[../images/04/dns_spoof_ip_settings.png|IPv4 Properties|350]]
>Finally, I select the "Use the following DNS server addresses" radio button and enter the IP address of my Ubuntu VM.  You might recall that the Ubuntu IP address was observed earlier in this activity.
>![[../images/04/dns_spoof_win_dns_ip.png|Windows DNS Configuration to Ubuntu|350]]
>With the Ubuntu DNS server configured on the Windows VM, I open the browser and navigate to www.google.com and observe that the page loads.  
>![[../images/04/dns_spoof_google_loads.png|Windows Google Load Success|300]]
>I then open a command prompt and run an `nslookup` to www.google.com to confirm that the IP address resolves to the address set in the dns.txt file on the Ubuntu DNS server.
>```bash
>nslookup www.google.com
>```
>![[../images/04/dns_spoof_win_google_nslookup.png|Windows Google Nslookup Resolution|600]]
>
>I also need to allowlist Google to be loaded within Edge without TLS.  Returning to Edge in the Windows VM, I navigate to `edge://settings/content/insecureContent` and then add `www.google.com` to the allow section.  This will simplify the attack for demonstration purposes, but know that an attacker could set up a HTTPS server with a certificate by doing a few extra steps.
>
>![[../images/04/activity_dnsspoof_edge_settings.png|Allow Insecure Google|600]]
>
>Next, I check the Ubuntu `dnsspoof` logs and see several entries in which the server is responding to the Window VM requests!
>![[../images/04/dns_spoof_ubuntu_valid_logs.png|Ubuntu DNS Spoof Valid Logs|600]]
>With the Windows and Ubuntu systems running in a healthy state and able to resolve the www.google.com domain correctly, I can prepare the attack.  I start by installing `dsniff` on the Kali machine after running an update.  My system was already up to date and `dsniff` was previously installed.
>```bash
>sudo apt update -y
>sudo apt install dsniff -y
>```
>![[../images/04/dns_spoof_kali_dsniff_install.png|Kali Install Dsniff|600]]
>Next, I set up a web file and serve it using a Python simple HTTP server.  This will serve as my malicious site that will target the victim.
>```bash
>mkdir /tmp/www
>cd /tmp/www
>echo "Not Google :)" > index.html
>sudo python3 -m http.server 80
>```
>![[../images/04/dns_spoof_kali_http.png|Kali HTTP Server|600]]
>In another terminal, I switch to the root user, set the ip_forward flag to "1" to allow my Kali machine to forward packets, and then set up `arpspoof` to target the Windows IP address and the Ubuntu DNS server.
>```bash
>sudo su -
>echo 1 > /proc/sys/net/ipv4/ip_forward
>arpspoof -i eth0 -t 192.168.4.168 192.168.4.169
>```
>![[../images/04/dns_spoof_arp_spoof_1.png|Kali ARP Spoof Windows|600]]
>With Kali now poisoning the Windows VM, I open another window and poison the target Ubuntu DNS server and Windows IP.
>```bash
>sudo arpspoof -i eth0 -t 192.168.4.169 192.168.4.168
>```
>![[../images/04/dns_spoof_arp_spoof_2.png|Kali ARP Spoof Ubuntu|600]]
>Now that Kali is poisoning both the Ubuntu and Windows VMs, convincing each that Kali is the other, and a malicious web server is running, I can finally set up the malicious DNS server on Kali.  First, in a new terminal, I create a `dns.txt` file with an entry that has the Kali eth0 IP address binded to www.google.com.  Then, I run the `dnsspoof` command on the interface eth0 referencing the `dns.txt` file.
>```bash
>echo "192.168.4.167 www.google.com" > dns.txt
>sudo dnsspoof -i eth0 -f dns.txt
>```
>![[../images/04/dns_spoof_kali_dnsspoof.png|Kali DNS Spoof Running|600]]
>I now have 4 terminals running: 2 with `arpspoof`, 1 with an HTTP server, and 1 with `dnsspoof`.  Now that the attack is fully staged, the last thing to do is to entice the victim to navigate to www.google.com.  The victim will send a DNS query that will be highjacked because of the ARP poisoning.  Our malicious DNS server will resolve the requested address with our attacker IP address that the victim will use to request the web page.  Finally, our Kali machine will serve the malicious page in replace of the actual Google site.  From the Windows VM, I open a private browser window, to avoid any caching, and navigate to http://www.google.com.
>![[../images/04/dns_spoof_trigger.png|Windows Victim Served Malicious Google Page|400]]
>The victim is served the malicious page!  Going back to Kali we can see the DNS spoof logs are resolving the request made by the victim.
>![[../images/04/dns_spoof_kali_spoof_logs.png|Kali DNS Spoof Logs|600]]
>While on the Kali VM we can see the HTTP logs serving the victim the malicious web site.
>![[../images/04/dns_spoof_http_logs.png|Kali HTTP Logs|600]]
>To enhance this attack further, I can clone the Google page and serve the site over HTTPS with a valid certificate.
## Dynamic Host Configuration Protocol (DHCP)
As previously discussed, NICs have their MAC addresses burned in during the manufacturing process.  However, IP address assignment works differently and is assigned by **dynamic host configuration protocol (DHCP)** servers.  These systems are often found within routers or as standalone servers.  DHCP is responsible for assigning IP addresses to LAN hosts and can be configured to provide IPs from a set or range.  They can also statically configure IPs to specific MAC addresses.  The DHCP server maintains a table that consists of each networked device's MAC, leased IP address, and an expiration of the lease.  When an IP address lease expires, a new lease will be reassigned that could be the same IP address previously assigned.  The client device receiving the IP address then validates the IP address by broadcasting to all other devices over ARP.  This validation process is designed to avoid collisions in the IP use and assignment.

![[../images/04/dhcp_basic.png|DHCP Lease|250]]

### DORA
When a device joins the network, it will not have an IP address until one is negotiated with the DHCP server.  In a process called *discover*, one of the first actions a new device performs is broadcast a message (or packet).  This broadcast message inquires who the DHCP server is to all other devices on the network.  The DHCP server will respond to the discover request with an *offer* message that includes an IP address for the new device to use.  The new device considers this offer, and if appropriate, sends a *request* message to the DHCP server asking to use the offered IP.  The DHCP server gets this request and adds an entry in the DHCP IP assignment table with the device's MAC, IP and expiration.  Afterwards, the DHCP server sends the final *acknowledge* message to the new device so it can register the IP address in its network stack.  The entire process of discover, offer, request, and acknowledge is referred to as **DORA**. 

![[../images/04/dhcp_dora.png|DHCP DORA Traffic|400]]

The figure above demonstrates the order and directionality of the DORA communications between a server and client.  Healthy network devices that receive discover requests simply ignore them.  But any network device could respond by claiming they are the DHCP server.
### DCHP Release
Another interesting request from a client to a DHCP server is the **release** packet.  The subject device will notify the server if it no longer needs the currently assigned IP address.  This is helpful in circumstances where the client prefers a different IP address.  To affect this change, the client sends the DHCP server a release packet and the server removes the existing MAC to IP binding in the IP table.  Misbehaving devices could spoof these requests causing the disassociation of IP addresses for target victims on a network.
### DHCP Risks
DHCP, like many other network protocols, inherently trusts devices connected on the network.  This is an acceptable risk if one can assume that physically connected devices were placed onto the network with permission.  However, it is imaginable that an attacker could physically install a device on a network, connect via Wi-Fi, or compromise an existing networked device.  Once an attacker connects to a network, they can inflict further damage as will be explored in the following paragraphs.   

Should the DHCP server become unavailable, the network would begin to fall into a degraded state as IP addresses expire.  Dynamic networks, that have devices being added and removed frequently, would quickly experience failing network services as new devices will not be able to utilize network resources, like routing to the internet.  Malicious actors can wage attacks that threaten the availability of the DHCP service for its clients and potentially cause a disruption to an entire network.  We will examine a type of DHCP DoS attack in the next section. 

Another threat to network security is the hijacking of the DHCP server.  This hijacking can lead to the compromise of systems on the network undermining confidentiality.  Because there is no default way to validate DHCP clients and servers on the network, there may not be much to prevent an attacker from impersonating or acting as the DHCP server.  The impact of this DHCP protocol weakness is caused by a malicious actor assigning themselves as the default gateway and taking control of the network traffic.
### DHCP Attacks
In the previous DHCP Risks section, a DoS threat was described which impacts the availability of the DHCP service on a network.  One DHCP DoS attack that we will explore in detail involves exploiting how the DHCP service natively works.  A **DHCP starvation** attack attempts to exhaust the available IP addresses for a network by consuming the entire range of available addresses.  The attacker repeatedly sends requests to the DHCP server for addresses until the entire range is used.  This blocks existing devices from renewing and new devices from procuring an address.  Eventually, all devices lose their IP addresses through expirations effectively shutting out everyone from the network.  The following diagram illustrates a DHCP starvation attack by an attacker blocking a new client.

![[../images/04/dhcp_starvation.png|DHCP Starvation Attack|300]]

Another interesting DHCP attack is a **DHCP spoofing** attack that has the goal of assigning an attacker-controlled device as the network's default gateway.  If the attacker can get the DHCP server and clients to assign and use the attacker's IP as the gateway, the attacker can inspect and manipulate all traffic within the network.  This attack works because the attacker acts as the DHCP server and responds to DHCP requests on the network before the real DHCP server has a chance.  As suggested in the figure below, DHCP responses include the default gateway address that would be defined by the attacker.  The victim then sends their outbound traffic to the attacker instead of the network's gateway!

![[../images/04/dhcp_spoofing.png|DHCP Spoofing Attack|300]]

>[!activity] Activity 4.5 - DHCP Spoofing Attack
>I'll demonstrate a DHCP spoofing attack using Ettercap, which provides a nice GUI to perform and to manage several networking attacks.  The Windows VM will act as my victim and I'll launch the attack from the Kali VM, both using the `Bridge Adapter` network modes.
>
> For the sake of the demonstration, I need to know the Windows VM's IP address and the gateway of the network.  This could be determined using NMAP or another host discovery tool.  I launch a command prompt and run `ipconfig` to view the needed network details of the victim.  It is on the 192.168.4.0/24 network, has the IP address 192.168.4.168, and shows the default gateway as 192.168.4.1.
> ```bash
> ipconfig
> ```
> ![[../images/04/dhcp_activity_win_net.png|Windows VM Network Settings|600]]
> Switching to the Kali machine, I run similar commands and confirm that it is on the same network as the Windows VM (192.168.4.0/24).
> ```bash
> ip a
> ```
> ![[../images/04/dhcp_activity_kali_net.png|Kali VM Network Settings|600]]
> While still on the Kali machine, I launch Ettercap as root using `sudo` and with the `-G` option to use the GUI.
> ```bash
> sudo ettercap -G
> ```
> ![[../images/04/dhcp_activity_ettercap.png|Ettercap GUI Homescreen]]
> The first step is to start Ettercap's sniffing utility on the interface from the network our victim is on, which is eth0.  Sniffing is started by pressing the checkmark button in the upper right corner of the application next to the ellipsis button.
> ![[../images/04/dhcp_activity_sniffing.png|Ettercap Sniffing Mode]]
> Once sniffing is initiated, the log pane appears at the bottom of the screen detailing the configuration and confirmation that Ettercap has started sniffing traffic.  Soon we will start seeing logs of packets being captured!  A few new buttons appear at the top of the Ettercap application including a menu represented by a globe next to where the sniffing/checkmark button was.  I can stop the network sniffing by pressing the stop button in the upper left corner.  However, I leave sniffing enabled during this attack.  To configure the attack, I press the globe icon and then DHCP Spoofing.
> ![[../images/04/dhcp_activity_globe.png|Ettercap Attack Menu Options|350]]
> After pressing the DHCP spoofing option of the menu, a dialog box pops up needing information for the attack.  I enter the victim Windows IP address in the "IP range", the network's subnet mask, and I put the IP address of Kali in the DNS server field.  These settings will instruct Ettercap to target the Windows machine and poison its network settings to think the Kali machine is the DNS server.
> ![[../images/04/dhcp_activity_config.png|DHCP Spoof Configuration|300]]
> Once the settings are entered into the fields, I press Ok to start the attack.  Eventually, the Windows VM will change its network gateway to the Kali machine.  To speed this along, I renew the Windows IP address forcefully to imitate an IP lease that expires.
> ```bash
> ipconfig /release
> ipconfig /renew
> ```
> ![[../images/04/dhcp_activity_renew.png|Windows IP Release and Renewal|600]]
> The default gateway now shows as 192.168.4.167 which is the Kali VM!  Going back to Kali's Ettercap application I can see DORA packets showing in the log pane.
> ![[../images/04/dhcp_activity_logs.png|DORA Packets in Ettercap Logs]]
> At this point any victim traffic will be routed through the Kali machine!
> 
### DHCP Security
Network switch devices can mitigate DHCP starvation and snooping attacks through built in security features.  During DHCP starvation attacks, the threat actor sends multiple requests to the DHCP server with different MAC addresses requesting issuance of new IP addresses.  These requests traverse the network switch sending the packets to the DHCP server.  Many managed network switches have a security setting called **port security** that is applied to each interface, or port, of the switch.  Port security can be set to allow a certain number of MAC addresses per interface.  If the number of MAC addresses associated with the interface exceeds the port security limit, then the switch will disable the interface blocking any further traffic.  Port security thresholds can be set to one or more MAC addresses allowed, usually the first address connected to the port.  A network administrator would then need to purposefully reopen the interface to allow traffic to flow again.  This security setting mitigates several network attacks including DHCP starvation as it shuts the misbehaving interface down early in the attack, as demonstrated in the figure below.

![[../images/04/dhcp_port_security.png|Port Security|400]]

The other type of attack we covered is the DHCP spoofing attack using a rouge DHCP server.  In this attack, the threat actor seeks to convince devices on the network that it is the gateway to the network.  Successful attacks empower the malicious actor the ability to inspect and manipulate traffic on the network.  These attacks can be mitigated using another managed network switch security setting called **DCHP snooping**.  This setting defines the interface on the switch on which the DHCP server resides.  Any DHCP response packets not generating from this interface will be dropped by the switch.  If an attacker claims to be the DHCP server from an interface that is not statically assigned, its packets will be dropped, thus preventing the attacker from achieving their malicious objectives.

![[../images/04/dhcp_snooping.png|DHCP Snooping|450]]

## Transmission Control Protocol (TCP)
We have already covered the basics of TCP in the previous chapter.  You may recall the introduction of the three-way handshake in which a client sends a SYN packet to the server, the server responds with a SYN+ACK, and the client sends an ACK packet before starting the transmission of data.  TCP is heavily used in networking with most popular protocols relying on it as a resilient means to communicate.  There is another packet sent by the client to the server that we did not cover in the last chapter, and it is called the **reset (RST)** packet.  This RST packet terminates a connection stream between the client and the server and is useful to keep networks tidy.  You can see this packet ending a transmission in the figure below.

![[../images/04/tcp_rst.png|TCP Reset Packet|250]]

The RST packet is used to notify the server that the client no longer intends to send data, and the server can end the connection in its network stack.  If a client needs to transmit data thereafter, it is required to reestablish a connection by engaging in the three-way handshake once again.
### TCP Threats
TCP, which resides in layer 4 of the OSI model, is subject to attacks with effects similar to other networking protocols.  Its placement in the middle of the network stack, encapsulating so many other protocols, makes it a prime target.  Disrupting TCP can cause higher order protocols, such as HTTP, to inherently fail since they depend on TCP.  Therefore, keeping a server's ability to maintain TCP connections is crucial for the availability of the service.  This makes TCP a candidate for *denial of service (DoS)* attacks in which the attacker attempts to disrupt the flow of TCP wrapped packets.  

Every TCP connection starts with a client SYN packet and then a server SYN+ACK response.  A misbehaving client can send repeated SYN packets causing the server to open a connection for each one.  These open connections eventually expire, but if a client or group of misbehaving clients sends many requests at once, they can quickly fill the TCP connection capacity of the server and block legitimate clients from establishing connections.  This coordinated DoS is referred to as a **TCP SYN flood** attack and is illustrated below.

![[../images/04/tcp_flood_attack.png|TCP Flood Attack|500]]

> [!activity] Activity 4.6 - TCP SYN Flood Attack
> I'll demonstrate such an attack from the Kali VM against the Ubuntu VM acting as a TCP server.  Using the `Bridge Adapter` settings on each VM, I'll configure the Ubuntu machine to serve HTTP traffic, a TCP protocol, and launch a **TCP SYN flood** attack on it.
> 
> After launching Ubuntu and opening a terminal, I start a simple HTTP server over port 80 using a Python built-in module.  Once the server is started, it sits idle waiting for incoming connections.
> ```bash
> sudo python3 -m http.server 80
> ```
> ![[../images/04/activity_flood_http_server.png|Ubuntu Python HTTP Server|600]]
> The next steps will require knowing the IP address and network interface.  Using another terminal, I run the `ip` command to identify this information.  I see the interface is enp0s3 and the IP address of the Ubuntu machine is 192.168.4.169.
> ```bash
> ip a
> ```
> ![[../images/04/activity_flood_ubuntu_net.png|Ubuntu Network Settings|600]]
> I want to be able to observe the TCP connections made on the server, so I use `tcpdump` on the primary network interface and filter requests for incoming port 80 requests.  The `-n` ensures only IP addresses are displayed and not host names while `-vvv` gives us a "very verbose" output.  Upon entering the command, the `tcpdump` application runs and waits for incoming connections to be captured.
> ```bash
> sudo tcpdump -i enp0s3 port 80 -n -vvv
> ```
> ![[../images/04/activity_flood_tcpdump_start.png|Tcpdump Started on Ubuntu|600]]
> On the Kali machine I can test access to the victim HTTP server using the `curl` utility in a terminal.  After running this command, I observed that the HTTP server responds with a directory listing page.
> ```bash
> curl 192.168.4.169
> ```
> ![[../images/04/activity_flood_kali_curl.png|Kali Curling Ubuntu Web Server|600]]
> The `curl` request from Kali was successful so I jumped back to the Ubuntu machine and observed that both the HTTP Python and the `tcpdump` windows log the requests!
> ![[../images/04/activity_flood_logs.png|Ubuntu Success Logs]]
> The victim server and attacking client are configured correctly so I am ready to launch the denial-of-service attack.  I will use the `hping3` tool to start a TCP flood attack against the Ubuntu server.  The `-c` command is the number of packets to be sent, the `-d` command is the byte size of each packet, the `-S` option specifies the SYN flag, and finally the `-w` options specifies the window size.  Once the command is run, it will repeatedly and send SYN packet after SYN packet opening connections on the Ubuntu server.
> ```bash
> sudo hping3 -c 15000 -d 120 -S -w 64 -p 80 --flood --rand-source 192.168.4.169
> ```
> ![[../images/04/activity_flood_attack.png|Hping Flood Attack from Kali|600]]
> The output of `hping` suggests it will not show any replies.  Back on the Ubuntu server, I can observe the `tcpdump` output is being flooded with requests!
> ![[../images/04/activity_flood_attack_logs.png|TCP Flood Attack Streaming Logs|600]]

TCP does not use encryption, leaving all its wrapper information exposed as plaintext.  However, TCP's data payload includes higher layer data that may be encrypted using transport layer security (TLS).  TCP connections can also be hijacked by attackers enabling them to take control of the connection, as demonstrated in previous man in the middle (MitM) attacks.  Without sufficient mitigating controls, an attacker can launch a **TCP reset attack** that will cause the client-server connection to terminate.  This attack requires the attacker to know the sequence number and sockets of the victim's connection, which can be obtained through brute force or packet sniffing.

![[../images/04/tcp_reset_attack.png|TCP Reset Attack|300]]

>[!activity] Activity 4.7 - TCP Reset Attack
>To demonstrate a TCP reset attack, I'll use the Kali VM on `Bridge Adapter` network mode.  The Kali machine will serve as both the client and the server using Netcat.  With Wireshark capturing packets, I'll establish a connection between the client and server and obtain details about the connection.  This information will be used with the Netwox tool that will send a RST packet and break the client-server connection.
>
>First, I start Wireshark through the applications menu and select the Loopback interface.  Double clicking this interface starts a packet capture.
>![[../images/04/activity_rst_wireshark_start.png|Kali Starting Wireshark on Loopback Interface]]
>With the packet capture running, I next need to set up the client and the server.  Starting with the server, I launch a terminal and use Netcat to listen on port 8000 for incoming connections with verbose output and keeping the connection alive.
>```bash
>nc -nvlp 8000
>```
>![[../images/04/activity_rst_server.png|Netcat Server Port 8000|600]]
>Launching another terminal (2nd), I use Netcat to establish a connection to the server listening on port 8000.  I use the home address 127.0.0.1 to make a connection on the loopback interface and then send a message `hello!` by typing into the terminal.  The connection remains open ready to take additional data and does not return us to the bash terminal.
>```bash
>nc 127.0.0.1 8000
>```
>![[../images/04/activity_rst_hello.png|Client Connection to Netcat Server 8000|600]]
>Immediately, I can observe that the server accepts the connection and displays the client's incoming message.  The output also shows the client port 34502 from which the connection originated.
>![[../images/04/activity_rst_connection.png|Incomming Connection from Client|600]]
>The client and server terminal Netcat connection simulates a typical TCP communication channel.  This connection will be the target of my attack.  As the attacker, I have a Wireshark packet capture running on the loopback interface which collected the client server connection.  Within Wireshark, I select the last TCP ACK packet and expand the TCP header to identify the `Sequence Number (raw)` value 2032347291 which I will use to send a RST and disrupt the client - server connection.
>![[../images/04/activity_rst_sequence_number.png|Sequence Number (raw) Identified in Wireshark]]
>I will use the tool Netwox to run this attack in a new terminal.  Netwox is not preinstalled in Kali, so I install it using the following command.
>```bash
>sudo apt update -y
>sudo apt install netwox -y
>```
>![[../images/04/activity_rst_netwox_install.png|Installing Netwox|600]]
>With Netwox installed, the sequence number captured, and the client and server sockets known, I am ready to break the connection.  I configure Netwox to point to the sockets and target the sequence number of the last ACK packet.  Upon running the command, I get an output of the TCP/IP packet that was sent.
>```
>sudo netwox 40 -l 127.0.0.1 -m 127.0.0.1 -o 8000 -p 34502 -B -q 2032347291
>```
>![[../images/04/activity_rst_netwox_attack.png|Netwox Attack on Connection|600]]
>Wireshark captures the RST packet sent by Netwox.
>![[../images/04/activity_rst_attack_capture.png|Wireshark RST Packet Captured]]
>Pulling up the client window shows that the connection terminated because the client is returned to the bash prompt!
>![[../images/04/activity_rst_closed.png|Client Connection Terminated|600]]
### TCP Security
There are several security measures that can be used to mitigate the threats to TCP.  A server's network TCP backlog threshold setting can be increased from its default value.  The backlog limits the number of outstanding three-way handshakes that are incomplete.  Because the protocol requires back and for communication and the client initiates the connection, it could take some time for the client to send the ACK packet, if ever.  The server's configuration will determine the maximum number of concurrent TCP connections allowed, and once full, will not allow any additional connections.  Therefore, increasing the number of the allowed backlog connections gives the server more capacity to handle an attack.  The backlog threshold does have an upper limit of what it can handle depending on the system's resources so there is still a risk of a flooding attack.  Internet connected services could leverage proxy or upstream internet service provider security to absorb backlogs of TCP connections.  Cloudflare offers a popular proxying service that fronts an HTTP service and has a great amount of capacity that can prevent or absorb TCP flood attacks.  

The risk of TCP reset attacks can be mitigated through cookies, sometime referred to as canaries.  In this context, a cookie is used as a special indication of a client and server connection allowing the server to authenticate the incoming TCP packet with the trusted client.  The **SYN cookie** is a server-side control that encodes the client information into a string value, called a cookie.  Each connection's cookie is stored in a server-side table and used as a reference for incoming connection requests.  Any request that does not authenticate or match with the cookie is dropped and the connection slot released for other client's use. 

Another cookie method, the **RST cookie**, mitigates attacks by validating clients beforehand.  In this strategy the server sends an invalid SYN+ACK packet to the client after receiving the initial connection and logs the transaction.  The server will not open any new TCP connections from the client until the client sends an RST packet in response to the server's invalid SYN+ACK request.  Once the client does send the RST packet, the server assumes the client acting responsibly and adds it to a server-side allow foregoing any additional RST cookie procedures for that client.
## Exercises

> [!exercise] Exercise 4.1 - ARP Spoof Attack
> In this task, you will create a VirtualBox NAT network.  From within this network, you will spoof the address of the gateway and victim interfaces to discreetly capture the victim’s traffic.  You will use the Ubuntu and Kali VMs under NAT Network mode network settings.
> #### Step 1 - Create NAT Network
> In your Host machine, start VirtualBox, select Tools, and then Network Settings. Select the “NAT Network” tab (underneath the Properties button).  With the NAT Network tab selected, press the Create button and observe that a new NAT network has been created named “NatNetwork.”
> #### Step 2 - Check Ubuntu Network Settings
> Start the Ubuntu VM in NAT Network mode and select the NatNetwork.  Login to the Ubuntu VM, launch a terminal, and check the IP address of the machine (victim) using the following command.
> ```bash
> ip a
> ```
> Check the default gateway address using the route utility. Observe the IP address of the gateway in the destination 0.0.0.0 entry. Note that this command may require the installation of network tools. 
> ```bash
> sudo apt update -y
> sudo apt install net-tools -y
> route -n
> ```
> #### Step 3 - Prepare ARP Spoof Attack
> Start the Kali VM in NAT Network mode and select the NatNetwork.  Login to the Kali VM, launch a terminal and switch user to root. 
> ```bash
> sudo su -
> ```
> Install dnsiff.
> ```bash
> apt update -y
> apt install dsniff -y
> ```
> Configure port forwarding.
> ```bash
> echo 1 > /proc/sys/net/ipv4/ip_forward
> ```
> Check the interface (eg eth0) and the IP address of the Kali VM. 
> ```bash
> ip a
> ```
> Launch an ARP spoof attack between the victim and the gateway. Note: replace the `<INTERFACE>`, `<UBUNTU_IP>` and `<GATEWAY_IP>` with their respective values observed from previous commands/steps. 
> ```bash
> arpspoof -i INTERFACE -t <UBUNTU_IP> <GATEWAY_IP>
> ```
> Start a new terminal (2nd) while keeping the first terminal running.  Switch user to root and launch another ARP spoof attack between the gateway and the victim (inverse direction).  Pay careful attention to the order of the IP addresses being targeted compared to the other ARP spoof attack running. 
> ```bash
> sudo su -
> arpspoof -i INTERFACE -t <GATEWAY_IP> <UBUNTU_IP>
> ```
> Open another terminal (3rd) and switch user to root.  Use `tcpdump` to capture http packets on the interface running the ARP Spoof attacks (likely eth0).  `Tcpdump` will be standing by waiting/listening for incoming traffic. Note: replace `<INTERFACE>` with the Kali interface that `arpspoof` is running on.
> ```bash
> sudo su -
> tcpdump -i INTERFACE -s 0 ‘tcp port http’ -vvv
> ```
> Watch this terminal running `tcpdump` when the attack is triggered. 
> #### Step 4 - Trigger the Attack
> From the Ubuntu victim VM, simulate a vulnerable HTTP GET request using `wget`. 
> ```bash
> wget http://www.example.com/?password=SuperSecret -O /tmp/test
> ```
> Observe that Kali’s running `tcpdump` terminal captures the victim’s traffic!  Manually search the traffic logs for the “SuperSecret” password. 


> [!exercise] Exercise 4.2 - Zone Transfer File
> Using your Ubuntu VM with `NAT` network settings, so it can reach the internet, perform DNS reconnaissance using "dnsdumpter.com" and perform a zone transfer using `dig`.
> #### Step 1 - Passive Zone Lookup
> Using the browser, navigate to "dnsdumpster.com" and lookup the domain “zonetransfer.me”. Review the records, subdomains, and information on the page. 
> #### Step 2 - Zone Transfer
> Find the nameservers of "zonetransfer.me" using `dig`.  From the Ubuntu terminal, run the following command to identify the nameservers. 
> ```bash
> dig +short NS zonetransfer.me 
> ```
> With a nameserver identified, transfer the zone file from the Ubuntu terminal.  Make sure to replace `NAMESERVER` with the domain of the server identified. 
> ```bash
> dig axfr zonetransfer.me @NAMESERVER
> ```
> Describe some of the interesting entries you found.


> [!exercise] Exercise 4.3 - DNS Spoofing
> The DNS Spoofing task will use the Ubuntu VM as a DNS server, the Windows VM as a victim DNS client, and the Kali VM as a malicious DNS server. The goal will be to get the Windows VM to resolve IP addresses from the Kali VM in a static network. Set up each VMs’ (Ubuntu, Windows, Kali) network settings to `Bridged Adapter` mode. 
> #### Step 1 - Setup DNS Server
> From the Ubuntu VM, install and configure the DNS server (using dnsspoof).  Within the Ubuntu terminal, modify your primary user account to use sudo. Make sure to replace `USER` with your username on the VM. 
> ```bash
> su -  
> usermod –aG sudo USER
> ```
> Reboot the VM for the sudo settings to take effect. Once rebooted, you will be able to run commands as the root user from your primary user account.  Next, install `dsniff` using the following command.  
> ```bash
> sudo apt install dsniff –y 
> ```
> After `dsniff` has been installed, look up the IP address of www.google.com to be used in a `dns.txt` file. Make sure to replace the `IP` with the IP address of www.google.com. 
> ```bash
> nslookup www.google.com 
> echo “IP www.google.com” > dns.txt 
> ```
> Identify the network interface of your Ubuntu VM by running the following command. The interface might be something like “enp0s3”. 
> ```bash
> ip a 
> ```
> With `dsniff` installed, the `dns.txt` file created, and the network interface identified, start the `dnsspoof` server. Make sure to replace `INTERFACE` with the network interface identified in the last command. 
> ```bash
> sudo dnsspoof -i INTERFACE -f dns.txt
> ```
> #### Step 2 - Configure Windows DNS Setting
> In this step, you will modify the Windows interface DNS settings to use the Ubuntu VM.  From the Windows VM, open the Control Panel's Network Connections panel. Right-click “Ethernet” and select “Properties” to launch the interface property window. With the interface properties window opened, select “Internet Protocol Version 4 (TCP/IPv4)” and press the “Properties” button. Select the “Use the following DNS server addresses:” radio button and enter the IP address of the Ubuntu VM.  Press “Ok” and close out the windows that were opened for the network settings. 
> ![[../images/04/dns_win_settings.png|Windows DNS Configuration]]
> You should see log activity in the Ubuntu `dnsspoof` terminal when running the following command from a Windows command prompt. 
> ```bash
> nslookup google.com
> ```
> #### Step 3 - Spoof DNS
> With the Ubuntu DNS server running, and the Windows VM configured to use the Ubuntu DNS resolver, launch a MitM + DNS Spoof attack from the Kali VM. Launch a terminal in the Kali VM and install `dsniff`. 
> ```bash
> sudo apt install dsniff -y 
> ```
> Identify the IP address of the Kali VM and add it to a `dns.txt` file for www.google.com. Make sure to replace `IP` with the IP address of the Kali VM. 
> ```bash
> ip a 
> echo “IP www.google.com” > dns.txt 
> ```
> Configure the Kali VM to forward IP addresses that will be used in the MitM attack. You will switch the user to root, set the process ip_forward flag to 1, and exit the root terminal. 
> ```bash
> sudo su - 
> echo 1 > /proc/sys/net/ipv4/ip_forward 
> exit
> ```
> With the Kali VM set to forward IP addresses, and while in a user terminal (not root), spoof the arp resolution between the Windows to Ubuntu VMs. Make sure to replace the `WIN_IP` with the IP address of the Windows VM and the `UBUNTU_IP` with the IP address of the Ubuntu VM. 
> ```bash
> sudo arpspoof -t WIN_IP UBUNTU_IP
> ```
> With Windows and Ubuntu traffic being spoofed, launch another Kali terminal and spoof the traffic between the Ubuntu and Windows VMs (opposite traffic flow from the last command). Make sure to replace the `WIN_IP` and the `UBUNTU_IP` IP addresses with the respective VM IP addresses. 
> ```bash
> sudo arpspoof -t UBUNTU_IP WIN_IP
> ```
> You should have two Kali terminals opened and each spoofing traffic between the Ubuntu and Windows VMs. Next, open a third terminal and identify the network interface of the Kali VM (might be eth0). 
> ```bash
> ip a 
> ```
> Within the third terminal opened, launch the `dnsspoof` attack. Make sure to replace the `INTERFACE` in the command with the name of the interface identified in the previous command. 
> ```bash
> sudo dnsspoof -i INTERFACE -f dns.txt
> ```
> #### Step 4 - Trigger Attack
> With the Kali VM spoofing traffic between the Windows and Ubuntu VMs, you are ready to observe the results of the attack.  If successful, you should see that www.google.com now resolves to the Kali VM's IP address. From the Windows VM terminal, lookup the IP address of www.google.com 
> ```bash
> nslookup www.google.com
> ```
> You should observe that www.google.com resolves to the Kali VM IP address.  If not, consider the following: 
> - Review your configurations 
> - Flush local DNS cache in the Windows VM with the following command: `ipconfig /flushdns`
> - Sometimes Windows will resort to IPv6 for DNS resolution, consider disabling it in the Ethernet properties.
> - Wait a few minutes and try again 
> #### Step 5 - Decommission
> After you have completed the lab, make sure to revert changes made to your Windows VM.  Consider restoring from a previous snapshot or manually turning the Firewall profiles on and removing the manual DNS server IP address on the Ethernet interface. 


> [!exercise] Exercise 4.4 - DHCP Spoofing
> This task will use the Windows and Kali VMs in network Bridge Adapter mode. The Kali VM will spoof DHCP using Ettercap and if successful, the Windows VM’s gateway IP will show the Kali VM IP address. 
> #### Step 1 - Observe Victim Gateway
> From the Windows VM command prompt, observe the IP and gateway addresses in the network settings using the following command. 
> ```bash
> ipconfig
> ```
> #### Step 2 - DHCP Spoof Attack
> Run the DHCP Spoof attack from the Kali VM with the Windows machine as the victim.  From a Kali VM terminal, observe the netmask and IP address using the following command. 
> ```bash
> ip a
> ```
> Launch Ettercap from the Kali VM terminal. 
> ```bash
> sudo ettercap -G
> ```
> With Ettercap running, select the check button (top bar) to accept the settings. Select the MitM Menu (globe icon) from the top bar and select DHCP Spoofing. Configure the DHCP spoofing settings with the following information and press Ok. Make sure to replace the `WINDOWS_IP` and the `KALI_IP` with the respective IP addresses. 
> 1. IP Pool = WINDOWS_IP 
> 2. Netmask = 255.255.255.0 
> 3. DNS Server IP = KALI_IP
> #### Step 3 Confirm Spoof
> If the DHCP spoof attack was successful, the Windows VM will resolve Kali as the network gateway. From the Windows VM terminal, renew IP settings with the following command. 
> ```
> ipconfig /release
> ipconfig /renew
> ```
> Observe that the new gateway settings show the Kali VM IP address! 


> [!exercise] Exercise 4.5 - TCP Reset Attack
> You will perform a TCP reset attack against a local client and server in this task.  Use the Kali VM with the `Bridge Adapter` network setting.
> #### Step 1 - Install Netwox
> From a Kali terminal, install Netwox using the following command.
> ```bash
> sudo apt install netwox -y
> ```
> #### Step 2 - Launch Wireshark
> From the Kali applications menu, launch an instance of Wireshark.  Select the `Loopback:lo` interface and start a packet capture (blue fin icon in the upper left).
> #### Step 3 - Setup the Server and Client
> Launch a new terminal and switch the user to root.  Then start a Netcat server listening on port 8000.
> ```bash
> sudo su -
> nc -nvlp 8000
> ```
> Launch another terminal and establish a connection to the server just created.  Once connected, type your name and observe the server's standard output in the server terminal.
> ```bash
> nc 127.0.0.1 8000
> YOUR_NAME
> ```
> Observe the open TCP connection port in the server window.  This port number will be needed in the next steps.
> #### Step 4 - Observe the Sequence Number
> Return to Wireshark and select the last ACK packet.  Find the packet’s raw Sequence Number (should be about 10 digits).  Find your sequence number as it will be needed in the following steps.
> #### Step 5 - Launch the Reset Attack
> Open a 3rd terminal and run the following command.  Make sure to change the `CLIENT_PORT` and `RAW_SEQ_NUM` to the values you found in the previous steps.
> ```bash
> sudo netwox 40 -l 127.0.0.1 -m 127.0.0.1 -o 8000 -p CLIENT_PORT -B -q RAW_SEQ_NUM
> ```
> Return to the terminal that has the client running and confirm that the connection was disconnected.  You should see a return to the shell and that you can no longer enter text that the server receives.