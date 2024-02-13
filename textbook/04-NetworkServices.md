# Defending and Attacking Network Technologies

![](../images/04/ethernet_shield.jpg)

There are many types of network solutions, services, and protocols (referred to as technologies here) that are of security interest.  In this chapter, you will gain an understanding of a handful of these technologies by learning how they generally work and their security implications.  We will explore how to secure them and the ways in which they can be attacked.  The goal of this chapter, like so many others in this textbook, is to construct a model when approaching technologies by first learning how they work and then how they can be broken.  This chapter will specifically cover address resolution protocol, dynamic host configuration protocol, domain naming system, transmission control protocol, and wireless technology.  Each topic is mutually exclusive but each section follows the same layout of explaining the basics, how they are attacked, and how to implement good security posture to protect them.

**Objectives**
1. Understand common network protocols and technologies.
2. Explain basic defense for network technologies.
3. Conduct attacks against DNS, DHCP, ARP, WiFi, and TCP technologies.

## Address Resolution Protocol
The last chapter introduced IP and MAC addresses while describing how they are generally used in networks through layers 3 and 4 of the OSI model.  These addresses are critical for computer communications across networks through network equipment like NICs, switches, and routers.  As previously described, each NIC is given a MAC address burned in at the factory.  Good behaving networked devices keep their MAC address static, meaning they never change.  But these addresses don't scale well across the internet as they lack the organization the IP address system provides.  Therefore the internet relies on IP addresses to route traffic to and from sources and destinations.  A solution, **address resolution protocol (ARP)** is needed that can resolve IP addresses to MAC addresses to ensure packets can traverse networks effectively.  ARP enables computers and switches to send packets among each other with each device maintaining an dynamic inventory of MAC addresses to IP ranges
### ARP Protocol
A group of computers connected to a LAN managed by a switch may periodically need to communicate with each other.  For example, a computer may need to send spooled print files to a networked printer to print documents.  In this example the computer will have the IP address of the printer, but the switch requires the MAC address to forward request to the printer.  The computer will send an **ARP request**, or *REQ*, packet through the switch to all devices on the network with the requestor's MAC address while asking "Who has the IP address xxx.xxx.xxx.xxx"?  Each device on the network receives the request and the device whose the IP address belongs to will prepare and transmit an **ARP response**, or *RES*.  This response declares "I have that IP address, my MAC address is xx.xx.xx.xx.xx.xx" and sends the message using the requestor's MAC address.  If no device responds, the request will hit the gateway and the address does not resolve.
![[../images/04/arp_protocol.png|ARP Requests and Responses|300]]
The diagram above demonstrates a functioning LAN with 3 devices requesting and responding through a network switch.  The request and response packets are very common on a network and can be observed in packet captures such as through the last chapter's Wireshark exercise.

> [!note] Note - Broadcasting
> The act of sending a packet to all devices simultaneously on a LAN is known as a *broadcast*.  
### ARP Cache/Table
Network devices, such as computers and switches, catalog the results of ARP messages into an **ARP table** or **ARP cache**.  This table stores the relationship between IP and MAC addresses for reference.  The protocol first checks if a MAC address is defined in the ARP table before broadcasting REQ packets to the LAN via the address 255.255.255.255.  If the MAC address for an IP is already known, the device won't send a broadcast address and instead create packets destined by the known MAC address.  Each entry, or row, in the ARP table holds the IP address, MAC address, and the entry type *static* or *dynamic*.  Static entries are set manually by system or network administrators  whereas dynamic entries are set by the ARP protocol discovery efforts.  ARP table entries also include expiration times where the entry will no longer be considered valid and will fall off the table.  The expirations help keep the table from only growing larger, and therefore slower, as devices are added and removed from the network.  In addition, IP addresses can change frequently so there could be new IP addresses for existing MAC addresses in the table.  Entries also specify which network interface the IP is associated with which is particularly useful for switches that have several interfaces.

> [!activity] Activity - ARP
> Let's demonstrate how ARP works using our lab environment.  I'll start the Ubuntu VM in NAT mode so it has connection to the internet and install the network packet capturing tool Tcpdump which works similar to Wireshark but is a command line tool.  Then I'll restart the Ubuntu VM and start the Windows VM both in `Host Only Adpater` to ensure they can reach each other.  With the environment setup, we will run a packet capture for ARP packets on the Ubuntu VM and invoke ARP requests and responses from the Windows VM.
> 
> With the Ubuntu VM started in `NAT` network mode, I'll open a terminal and run the apt install command to install net-tools which includes Tcpdump.  Note, it is a good practice to first update your system before installing new tools.
> `sudo apt update -y`
> `sudo apt install net-tools`
> ![[../images/04/arp_nettools_install.png|600]]
> I power off the Ubuntu VM after net-tools is installed.  I then start both Windows and Ubuntu VMs in `Host Only Adpater` network mode.  With the Windows VM started and logged in, I start a command prompt and check the machine's IP address using ipconfig.
> `ipconfig`
> ![[../images/04/arp_win_ip.png|Windows IP Check|600]]
> Similarly, I'll log into the Ubuntu VM, start a terminal session, and check its IP address using the ip command.  We can see that the Ubuntu VM's IP address is assigned on the `enp0s3` interface which will be used later when we run Tcpdump.
> `ip a`
> ![[../images/04/arp_ubuntu_ip.png|Ubuntu IP Check|600]]
> Both VMs are observed to be on the 192.168.56.0/24 subnet which means they should be reachable.  Next, I'll check the ARP table on the Windows VM using the arp command to see what entries it currently has.  The `-a` option shows all entries.
> `arp -a`
> ![[../images/04/arp_win_table.png|ARP Table Entries|600]]
> While there are several entries, we do not see on for the Ubuntu IP address.  This means that the Windows VM hasn't made any recent connections to Ubuntu.  Jumping back onto the Ubuntu VM I'll start a packet capture using Tcpdump setting the interface with the `-i` option and only capturing `arp` packets.  I'll also use the `-vv` for very verbose output to give us details on the captured packets.
> `sudo tcpdump -i enp0s3 arp -vv`
> ![[../images/04/arp_tcpdump_listen.png|Tcpdump Listening|600]]
> The Tcpdump command remains idle waiting for incoming and outgoing packets.  I'll run the ping utility on the Windows VM to initiate a MAC resolution since the Windows VM does not yet have it in the ARP table.  Back on the Windows machine I run the following ping targeting Ubuntu.
> `ping 192.168.56.251`
> ![[../images/04/arp_ping.png|Ping Ubuntu|600]]
> The ping was successful!  Now I'll recheck the Windows VM ARP table to see if an entry exists for the Ubuntu IP address using the arp command.
> `arp -a`
> ![[../images/04/arp_table_2.png|ARP Table Recheck|600]]
> Awesome, the Ubuntu VM has a record now in the Windows VM ARP table.  We can observe the Ubuntu MAC address now!  Let's review the packets capture on the Ubuntu VM's running tcpdump.
> ![[../images/04/arp_captured_packets.png|Tcpdump Captured ARP Packets|600]]
> The packet capture collected two ARP packets.  The first packet, unhighlighted, displays the REQ from our Windows VM at 192.168.56.253.  The second packet, highlighted in white, shows the Ubuntu RES packet including the Ubuntu MAC address 08:00:27:6d:b9:2e.
### MiTM ARP Attacks
Consider the implications of the ARP protocol as demonstrated in the last activity.  The packets captured in Tcpdump displayed the request and the response in a healthy network.  But this is very trusting by nature as any device on the network receives the packets and can respond, even if they don't hold that IP address.  By default, there isn't much stopping another device from claiming they hold the IP address and responding with their own MAC address.  This could trick a victim into communicating with the wrong device!

An unauthorized entity that intercepts network traffic, usually by proxying or funneling that traffic, is known as a **man in the middle (MitM)** attack.  This attack requires the threat actor to place themselves between at two, or more, entities and routes traffic between them.  The victims of this attack think they are communicating directly with their target but in fact all traffic is being sent to the attacker instead.  The attacker's device will receive the victim's traffic, inspect or manipulate it, and forward it to the appropriate destination.  The receiver of the attacker proxy traffic responds the the request sending it to the attacker who again inspects or manipulates the data before relaying back to the original victim.

The ARP protocol can be abused by an attacker on a network through responses to victim's ARP requests.  An attacker can poison a victim's ARP table by flooding the victim ARP RES packets claiming to be at an IP address it is not.
![[../images/04/mitm_arp.png|MitM ARP Poisoning|400]]
The figure above captures the poisoning of devices on a network by a malicious actor.  Devices send request packets and the attacker responds to each with poisoned packets claiming to be at the request IP addresses.

>[!activity] Activity - ARPSpoof
>Let's demonstrate the ARP poisoning and spoofing attack in our lab.  I'll use the Kali and Ubuntu VMs in a virtual network.  The Kali VM will poison the ARP table of the victim Ubuntu machine.  The traffic from Ubuntu will then be routed through the attacker Kali machine and available for inspection.
>I'll begin by creating a virtual NAT network in VirtualBox by going to Tools, Network Settings.
>![[../images/04/activity_arp_nat_network.png|VirtualBox Network Settings|600]]
>With the VirtualBox network settings opened, I'll select the "NAT Network tab" and press the "Create" button.  This will cause a new "NatNetwork" to be generated with the IPv4 subnet 10.0.2.0/24.
>![[../images/04/activity_arp_nat_created.png|VirtualBox NAT Network Creation|600]]
>I then set the Ubuntu and Kali VM's network settings to use the "NAT Network" adapter and specify the newly created "NatNetwork" before I start each VM.  This ensures both VMs are on the isolated virtual network we just created.
>![[../images/04/activity_arp_vm_network.png|Ubuntu VM Network Settings NatNetwork|450]]
>After launching the Ubuntu VM I log in, start a terminal session and run the ip command to observe the address 10.0.2.7 which is in our virtual NAT network subnet.
>```
>ip a
>```
> ![[../images/04/activity_arp_ubuntu_ip.png|Ubuntu VM IP Address|600]]
> Still on the Ubuntu machine I run the route command to identify the default gateway 10.0.2.1 in the destination placeholder address 0.0.0.0.  The following screenshot show the result of this command in a table that is word wrapped so I've highlighted the table entry.  This entry identifies the virtual switch is located at 10.0.2.1.  The `-n` option leaves the IP addresses shown instead of resolved domain names.
> ```
> route -n
> ```
> ![[../images/04/activity_arp_route.png|Ubuntu Default Gateway Route|600]]
> I'll start setting up the attack from the Kali box by first opening a terminal and switching the user to the root user.  Many of the commands needed for this attack require elevate privileges within Kali so it'll be easiest to perform all actions as the root user.  Then I'll install dsniff which includes several utilities including arpspoof that we'll use to launch the ARP poisoning attack.  As a reminder, it is always good practice to update the system prior to installing new software as it may require dependencies to be up to date.
> ```
> sudo su -
> apt update -y
> apt install dsniff -y
> ```
> ![[../images/04/activity_arp_dsniff_install.png|Kali Dsniff Installation|600]]
> Before we use the newly installed arpspoof utility in dsniff we need to configure the Kali machine to forward IP packets.  This will ensure the victim's traffic reaches its desired destination and returns an expected result while helping the attack remain discrete.  We accomplish this task by setting the value "1" to the `ip_forward` setting under running processes.
> ```
> echo 1 > /proc/sys/net/ipv4/ip_forward
> ```
> ![[../images/04/activity_arp_ipforward.png|Kali IP Forwarding Setting|600]]
> To use arpspoof we will need to identify which network interface to configure the command with.  A list of interfaces can be identified using the ip command.  Here we see the primary interface is "eth0" which has an IP address of the NatNetwork.
> ```
> ip a
> ```
> ![[../images/04/activity_arp_kali_interfaces.png|Kali Network Interface List|600]]
> Using arpspoof, I will tell the victim that the Kali address is the default gateway using the interface, victim IP, and gateway as options in the command.  The interface is configured using the `-i` option while the target is defined under the `-t` option.  Once entered, the tool immediately begins flooding the victim with ARP RES packets claiming the Kali VM's IP on interface eth0 is the gateway.  Eventually the victim will add these claims in the ARP table and start sending traffic to Kali instead of the gateway.  Recall that we learned of the Ubuntu IP address and the gateway from the commands ran on the Ubuntu machine, but they could just as well been discovered through network reconnaissance efforts, like using NMAP.
> ```
> arpspoof -i eth0 -t 10.0.2.7 10.0.2.1
> ```
> ![[../images/04/activity_arp_poison_victim.png|Kali ARP Poisoning Victim|600]]
> With the ARP poisoning running against the victim Ubuntu machine, I'll setup another arpspoof targeting the default gateway.  The purpose here is to poison the gateway into thinking that the Kali machine is the victim.  The command is similar to the previous command except the IP address for the victim and the gateway are in swapped positions.  I open another terminal and switch the user to root then run arpspoof again.
> ```
> sudo su -
> arpspoof -i eth0 -t 10.0.2.1 10.0.2.7
> ```
> ![[../images/04/activity_arp_poison_gateway.png|Kali ARP Poisoning Gateway|600]]
> Kali now has two open terminals each running arpspoof aiming to poison the ARP tables of the gateway and the victim.  Once they are both adequately poisoned they will both send traffic to the Kali machine an Kali will forward the packets to their intended destination.  At this point we can observe the traffic using tcpdump packet capture using.  I'll specify tcpdump to use the default snapshot length using the `-s 0` option and filter the traffic to http traffic only.  I'll also use the `-vvv` for very very verbose output configuration.  Tcpdump will be ran with one more terminal, our third instance, in the Kali machine and running as root.
> ```
> sudo su -
> tcpdump -i eth0 -s 0 'tcp port http' -vvv
> ```
> ![[../images/04/activity_arp_capture.png|Kali Tcpdump HTTP Packet Capture|600]]
> Any HTTP packets should appear in our tcpdump packet capture running in Kali now.  Now we can demonstrate the packet sniffing via MitM by invoking an HTTP request from the victim Ubuntu machine.  Switching back to the Ubuntu machine I make an http request to example.com with password as a GET parameter using the wget command.  I'll also output the text to a temporary test file.
> ```
> wget http://www.example.com/?password=SuperSecret -O /tmp/test
> ```
> ![[../images/04/activity_victim_http_req.png|Ubuntu HTTP Request|600]]
> We can see that the request to example.com succeeded without any noticeable delay or issue.  Jumping back to the Kali machine we can see HTTP traffic was capture in the tcpdump output.  Scrolling up through the logs we can see both the request and the response from example.com that includes the victim's password in the GET request!
> ![[../images/04/activity_arp_password_captured.png|Kali Captured HTTP Packets|600]]

> [!exercise] Exercise - ARP Spoof Attack
> In this task you will create a VirtualBox NAT network and spoof the address of the gateway and victim interfaces to discretely capture the victim’s traffic.  You will use the Ubuntu and Kali VMs under NAT Network mode network settings.
> #### Step 1 - Create NAT Network
> In your Host machine, start VirtualBox, select Tools, and then Network Settings. Select the “NAT Network” tab (underneath the Properties button).  With the NAT Network tab selected, press the Create button and observe a new NAT network has been created named “NatNetwork”. 
> #### Step 2 - Check Ubuntu Network Settings
> Start the Ubuntu VM in NAT Network mode and select the NatNetwork.  Login to the Ubuntu VM, launch a terminal, and check the IP address of the machine (victim) using the following command.
> ```
> ip a
> ```
> Check the default gateway address using the route utility. Observe the IP address of the gateway in the destination 0.0.0.0 entry. Note that this command may require the installation of network tools. 
> ```
> sudo apt install net-tools
> route -n
> ```
> #### Step 3 - Prepare ARP Spoof Attack
> Start the Kali VM in NAT Network mode and select the NatNetwork.  Login to the Kali VM, launch a terminal and switch user to root. 
> ```
> sudo su -
> ```
> Install dnsiff.
> ```
> apt install dsniff -y
> ```
> Configure port forwarding.
> ```
> echo 1 > /proc/sys/net/ipv4/ip_forward
> ```
> Check the interface (eg eth0) and the IP address of the Kali VM. 
> ```
> ip a
> ```
> Launch an ARP spoof attack between the victim and the gateway. Note: replace the `<INTERFACE>`, `<UBUNTU_IP>` and `<GATEWAY_IP>` with their respective values observed from previous commands/steps. 
> ```
> arpspoof -i INTERFACE -t <UBUNTU_IP> <GATEWAY_IP>
> ```
> Start a new terminal (2nd) while keeping the first terminal running.  Switch user to root and launch another ARP spoof attack between the gateway and the victim (inverse direction).  Pay careful attention to the order of the IP addresses being targeted compared to the other ARP spoof attack running. 
> ```
> sudo su -
> arpspoof -i INTERFACE -t <GATEWAY_IP> <UBUNTU_IP>
> ```
> Open another terminal (3rd) and switch user to root.  Use tcpdump to capture http packets on the interface running the ARP Spoof attacks (likely eth0).  Tcpdump will be standing by waiting/listening for incoming traffic. Note: replace `<INTERFACE>` with the Kali interface that arpspoof is running on.
> ```
> sudo su -
> tcpdump -i INTERFACE -s 0 ‘tcp port http’ -vvv
> ```
> Watch this terminal running tcpdump when the attack is triggered. 
> #### Step 4 - Trigger the Attack
> From the Ubuntu victim VM, simulate a vulnerable HTTP GET request using wget. 
> ```
> wget http://www.example.com/?password=SuperSecret -O /tmp/test
> ```
> Observe Kali’s running tcpdump terminal captures the victim’s traffic!  Manually search the traffic logs for the “SuperSecret” password. 
> 
### Securing ARP
The ARP protocol is very permissive as demonstrated in the previous pages.  There are several controls that can be applied to help mitigate the risks imposed by ARP.  Higher layer traffic, such as HTTP in layer 7, can use encryption technologies like TLS to encrypt packet data fields.  Using encryption ensures that if packets are intercepted by an attacker are not readable, at least not without additional work.  It is conceivable that an attacker could intercept key exchanges or even mock a key exchange tricking the user to use the attacker's encryption keys.

Because the ARP spoof attack relies on the use of dynamic entries in the ARP table, a network administrator could use only static entries ensuring they are not hijacked by the attacker.  This will prevent the attacker from poisoning the ARP table and launching an effective MitM attack.  However, it isn't always feasible for an administrator to manage static entries as networks can grow large, complex, and be very dynamic.  For larger networks where static assignments are not feasible, administrators should use *dynamic ARP inspection (DAI)* that leverages the *DHCP snooping* table on a network switch to inspect ARP packets against the known good MAC and IP associated entries.  Any packets that violate DAI will be dropped and prevent an attacker from succeeding in an ARP poisoning attempt.  We will explore DHCP snooping security and DAI in a little more detail in the DHCP section of this chapter.

Another mitigation strategy is to use a segmented network design where networks are broken up into smaller networks separated by a physical or virtual router.  The ARP spoofing attack is only effective against devices within a LAN and by separating devices into smaller LANs the impact of the attack can be reduced while the threat persists.
## Domain Name System
Networked devices reach other networked devices through the use of IP addresses.  These addresses enable traffic to reach their ultimate destinations through routers, layer 4 devices, which interpret the networks they belong to.  IP addresses work well for computer systems, but are not ideal for human use as they don't convey meaning or context very well.  For example, when needing to search for something on the internet it is much more convenient for a user to remember and navigate to google.com instead of 142.250.189.238.  The system that allows the use of names instead of IP addresses is called **domain name system (DNS)**.  This system is supported by various servers on the internet, and sometimes within LANs, that resolve domain names to IP addresses.  A user can enter a name whose IP address is looked up by the network device and allows traffic to reach its ultimate destination.
![[../images/04/dns_resolution.png|DNS Resolution of Google|300]]
### DNS Infrastructure
The DNS services use UDP port 53, and sometimes TCP port 53 for zone transfers, to conduct domain name resolutions.  When a client, such as a browser, requests an IP address of a domain it first looks locally within its host configuration *host file* for any overriding entries.  If none are found in the hosts file that match the request the host then requests resolution via port 53 to the *DNS resolver*, which is a server that stores a cache of domain to IP address bindings.  The DNS resolver is often a router, as in many home or small office networks, but can also be a stand alone server dedicated to the task.  Regardless, if the resolver does not have an accompanying entry, it will reach out to the *top level domain (TLD) nameserver* from the *root server*, such as ".com", to identify the which *authoritative server* to make the request to.  The authoritative server will holds the source of truth for the IP to domain binding and ultimately responds with the IP address back to the client.  With the IP address now known, the client can make the request to the respective server.
![[../images/04/dns_infra.png|DNS Infrastructure Flow|400]]
The image above demonstrates the flow of a DNS resolution.  Each server will store, or *cache*, the result of DNS records in its records for swifter response times.  The propagation of these records can take some time and may also depend on the record's expiration.
### DNS Records
A DNS authoritative server holds various entries, or **DNS records**, that configure the relationships between IP addresses and domain names.  The following table describes some of the more common records used with the DNS system.

| Record Name | Description |
| ---- | ---- |
| A | Apex record that holds the IPv4 address for a domain |
| AAAA | Holds the IPv6 address for a domain |
| CNAME | Conocal name, or Alias name, for a domain and subdomains |
| MX | Mail exchange that directs emails to email servers |
| TXT | Text record often used to verify domain ownership |
| NS | Nameserver records |
| SOA | Start of authority containing admin information |
| SRV | Service port |
| PTR | Pointer record providing reverse lookups providing domains for an IP address |
Network administrators set these records depending on the needs of the network.  The "A" record is used as the primary use case for DNS as it provides the IP address for the given domain name.  Sometimes other domains can point to the same IP address causing the need for an alias or CNAME record.  This record is also used when a domain has one or more subdomains that point to other IP addresses.  A common subdomain is *www* but a domain have any compliant value as a subdomain or even subdomains of a subdomain.
### Zone Transfer
While DNS servers face the internet and serve anonymous inquires, DNS records are typically not advertised.  For example, you can't go to Google's authoritative server and download all DNS records, such as CNAME and MX records.  These records are not secrets but advertising them unnecessarily exposes information lower the bar for malicious actors to identify targets of an organization.  However, because records are public there is nothing stopping anyone from aggregating this information centrally and providing a lookup service, such as dnsdumpster.com.

Relying on a single authoritative server could impose availability risks with a domain.  For instance, when the server needs updates it will temporarily go offline resulting in needless downtime for a domain, or website.  Therefore, most administrators will ensure that they have at least one other authoritative server to maximize the availability of their domain in the DNS system.  Keeping both servers in sync with the same records then becomes a chore because the administrator would have to update both servers every time there is one update.  Indeed, if they managed a fleet of such servers there is a higher chance of missing one causing unusual and difficult to identify issues.  Therefore, many administrators will establish automation leveraging **zone transfers** over TCP port 53 that enables the syncing, or copying, of domain zones and all their records between authoritative server clusters.  However, as mentioned earlier in this section, an administrator would want to avoid exposing the zone transfer service to unauthorized users and must ensure access to this port and service is restricted to allowed sources.

>[!activity] Activity - Zone File
>Let's demonstrate some of what we've learned so far on DNS records and zone transfers.  I'll use dnsdumpster and investigate Google's domain to see what records have been publicly collected.  Then I'll attempt a zone transfer of Google's domain before demonstrating a live zone transfer on a vulnerable by design domain.
>
>Using the Ubuntu VM with `NAT` network mode, to ensure access to the internet, I'll open the default browser and navigate to dnsdumpster.com.  Once at the site, I enter `google.com` into the domain and review the results.
>![[../images/04/dnsdumpster.png|DNS Dumpster Google Domain Results Overview|600]]
>The site displays geographic pins where the Google servers are located.  Scrolling down the page shows NS, MX, and TXT records that have been cataloged.
>![[../images/04/dnsdumpster_records.png|DNS Dumpster Google Records]]
>A number of "A", or host, records are also itemized.  Subdomains are also listed by pressing the grid icon under the hostname.
>![[../images/04/dnsdumpster_host.png|DNS Dumpster Google Host Records]]
>Such passive review of a domain is useful but incomplete as only discovered records are list and some of them could not longer be valid.  To collect the entire record set of a  zone, we can use the dig utility.  I open a terminal on the Ubuntu VM and first lookup the nameservers of google.com.  With the nameservers identified, I use the dig command with the `axfr` to request a zone transfer for google.com from one of its nameservers.
>```
>dig +short NS google.com
>dig axfr google.com @ns3.google.com
>```
>![[../images/04/dig_google.png|Attempted Google Zone Transfer With Dig|600]]
>Unfortunately, the transfer failed because there is not available service from the Ubuntu VM.  To demonstrate what a zone transfer looks like, we can use the zonetransfer.me domain using the same commands.
>```
>dig +short NS zonetransfer.me
>dig axfr zonetransfer.me @nsztm1.digi.ninja
>```
>![[../images/04/zone_transfer_me.png|Successful Zone Transfer|600]]
>The zone transfer succeeded and displayed all the records of the domain!  This could be useful information for an attacker while performing reconnaissance looking for weak targets.

> [!exercise] Exercise - Zone Transfer File
> Using your Ubuntu VM with `NAT` network settings, so it can reach the internet, perform DNS reconnaissance using dnsdumpter.com and perform a zone transfer using dig.
> #### Step 1 - Passive Zone Lookup
> Using the browser, navigate to dnsdumpster.com and lookup the domain “zonetransfer.me”. Review the records, subdomains, and information on the page. 
> #### Step 2 - Zone Transfer
> Find the nameservers of zonetransfer.me and perform a zone transfer.  From the Ubuntu terminal, run the following command to identify the nameservers. 
> ```
> dig +short NS zonetransfer.me 
> ```
> With a nameserver identified, transfer the zone file from the Ubuntu terminal. Make sure to replace `NAMESERVER` with the domain of the server identified. 
> ```
> dig axfr zonetransfer.me @NAMESERVER
> ```

### DNS Threats
There are at least a few threats to DNS that must be considered when securing the system.  Should the system become unavailable it could result in clients being unable to resolve the domain names needed to access internet services of the organization.  Such a risk could be caused by the threat of *denial of service (DoS)* attacks where an attacker causes the DNS servers to be offline.  To mitigate such attacks the support of a vendor, such as NetScout, could be configured where DNS queries must first pass through proxies that inspect malicious traffic and discard them before reaching authoritative servers.  Another risk to the system is the takeover of the domain, such as a lapse in upkeep of the domain or the risk of an account takeover with the *registrar* such as GoDaddy.  Administrators should ensure their registrar contact details are up to date, multifactor authentication and strong passwords are used.  An interested, or malicious, third party could procure the domain and takeover any new records for the domain or perhaps steal credentials to the registrar and expel other administrators from accessing the registrar's web console.  Yet another risk to DNS is by attacks of the protocol itself in which an attacker convinces devices it is the DNS server (root, authority, or resolver) and replaces domain queries with malformed results.  Such a risk is mitigated using *DNSSEC* which authenticates and validates resolver responses to domain queries.

A **local cache poisoning** attack, where the attacker poisons or spoofs DNS response through the local hosts file, can cause victims to receive malicious DNS responses.  The victim requests a domain and receives an IP address that is in the control of the attacker.  Such an attacker controlled setup enables them to more easily trick users to phishing sites that can harvest the victim's credentials for example.
![[../images/04/local_cache_poisoning.png|Local Cache Poisoning|200]]
Building from the DNS Infrastructure diagram shared earlier, the image above demonstrates the local cache poisoning attack wherein the attacker sets the domain to IP binding in the hosts file which directs the victim to an attacker controlled server.  The DNS resolver could also be compromised in a **remote cache poisoning** attack.  Here, the attacker has the same objective of replacing domain to IP bindings with malicious IPs to meet an attack objective.  Borrowing again from the DNS Infrastructure diagram, the image below illustrates an attacker compromise of the DNS resolver, stifling the DNS response.
![[../images/04/remote_cache_poisoning.png|Remote Cache Poisoning|375]]
Yet another attack where the actor seeks to hijack the DNS response with a malicious one is the **malicious DNS server**.  In this attack the advisory sets up their own DNS resolver on the network and influences hosts to use it over the real resolver.  This has the same impact as the remote cache poisoning attack but avoids the need of compromising the real resolver.
![[../images/04/malicious_dns_server.png|Malicious DNS Server|375]]

The diagram above shows the malicious DNS server sitting on a network and responding to client requests.  An attacker could attack the DNS servers directly through a **DNS flood attack** in an attempt to cause the server to fail to respond to client requests breaking the service for all clients.  This is a type of denial of service attack which disrupts the normal operation of DNS services.  Unless the server is particularly under resourced, or a vulnerability exists that exposes the DNS service to this type of attack, the attacker could use several devices, or a *bot army*, to send the requests and overwhelm the DNS server.  The diagram below demonstrates this attack blocking the client from using the resolver.
![[../images/04/dns_flood_attack.png|DNS Flood Attack|350]]
Some networks connected to the internet are limited by the ports and applications that are allowed to leave the network.  A good security posture ensures that only needed traffic is allowed to leave the network which can often be limited to HTTP for example.  Another common service often allowed to egress the network, even in highly secured networks, is DNS over port 53.  An attacker needing to exfiltrate data, such as file transfer, won't be able to move files out of the network using a protocol like file transfer protocol (FTP); however, an attacker could abuse the DNS service to exfiltrate data.  Even if an attacker could move files over FTP, or some other file transfer protocol, they may choose not to in an effort to evade detection and use DNS as it is less likely to be noticed.  

To accomplish **DNS tunneling exfiltration**, the attacker segments a file into small clips and encodes it into a compliant character set (a-z0-9-.).  Each segment is then used as the subdomain of an attacker control domain and resolver.  The victims resolver won't recognize the subdomain and will initiate the request to the attackers authoritative server.  The attacker controlled authoritative server logs are then compiled to reassemble the subdomains and decode naming convention back into the original file!  Such an effort expects that the attacker is already in the network and has acquired sensitive information.  But it should be taken seriously as losing control of data is often a threshold organizations want to avoid.

>[!activity] Activity - DNS Spoofing
>I'll demonstrate a DNS spoofing attack using the three VMs, Kali, Ubuntu, and Windows using `Bridge Adpater` network settings.  The Kali VM will act as the attacker, the Ubuntu machine will be configured as a DNS resolver using dnsspoof, and the Windows VM will be our victim.
>
>Starting with the Ubuntu machine, I install dsniff after I update the system.
>```
>sudo apt update -y
>sudo apt install dsniff -y
>```
>![[../images/04/dns_spoof_ubuntu_dsniff.png|Ubuntu Installing Dsniff|600]]
>My DNS server will only resolve www.google.com but I first need to know its IP address.  I'll use nslookup to find the IP address and then create a domain to IP binding in a dns.txt file.
>```
>nslookup www.google.com
>echo "142.250.189.164 www.google.com" > dns.txt
>```
>![[../images/04/dns_spoof_dnstxt.png|Setting Up DNS Record|600]]
>Using the ip command I identify the interface that the DNS server will run on.  Then I start dnsspoof to server the dns.txt records on that interface.  Dnsspoof isn't a reliable DNS server application and is being used here for ease of use.
>```
>ip a
>sudo dnsspoof -i enp0s3 -f dns.txt
>```
>![[../images/04/dns_spoof_dns_server.png|DNS Server Running on Ubuntu|600]]
>With the DNS server up and running ready to resolve www.google.com, I switch to the Windows VM and configure its DNS resolver to the Ubuntu IP address.  I right-click the network tray icon and "Open Network & Internet settings".
>![[../images/04/dns_spoof_win_net_settings.png|Windows Launch Network Settings|300]]
>This launches the Network Settings window.  I then press the "Change adapter options" under the "Advanced network settings" section.
>![[../images/04/dns_spoof_win_net_options.png|Windows Change Adapter Options|500]]
>The "Network Connections" window is opened displaying our network interfaces.  I right-click the Ethernet entry and select "Properties" from the context menu options.
>![[../images/04/dns_spoof_ethernet_properties.png|Ethernet Properties|350]]
>Within the Ethernet Properties window, I select the "Internet Protocol Version 4" option and press the "Properties" button to open its properties.
>![[../images/04/dns_spoof_ip_settings.png|IPv4 Properties|350]]
>Finally, I select the "Use the following DNS server addresses" radio button and enter the IP address of my Ubuntu VM.  You might recall the Ubuntu's IP address was observed earlier in this activity.
>![[../images/04/dns_spoof_win_dns_ip.png|Windows DNS Configuration to Ubuntu|350]]
>With the Ubuntu DNS server configured on the Windows VM, I'll open the browser and navigate to www.google.com and observe that the page loads.  
>![[../images/04/dns_spoof_google_loads.png|Windows Google Load Success|300]]
>I'll then open a command prompt and run an nslookup to www.google.com and confirm the IP address is resolved to the IP address set in the dns.txt file on the Ubuntu DNS server.
>```
>nslookup www.google.com
>```
>![[../images/04/dns_spoof_win_google_nslookup.png|Windows Google Nslookup Resolution|600]]
>Next I check the Ubuntu dnsspoof logs and see several entries where the server is responding to the Windows requests!
>![[../images/04/dns_spoof_ubuntu_valid_logs.png|Ubuntu DNS Spoof Valid Logs|600]]
>With the Windows and Ubuntu systems running in a healthy state and able to resolve the www.google.com domain corretly, I can start preparing the attack.  I start by installing dsniff in the Kali machine after performing an update.  My system was already up to date and dsniff was previously installed
>```
>sudo apt update -y
>sudo apt install dsniff -y
>```
>![[../images/04/dns_spoof_kali_dsniff_install.png|Kali Install Dsniff|600]]
>Next, I'll setup a web file and serve it using a Python simple HTTP server.  This will serve as our malicious site we'll target the victim with.
>```
>mkdir /tmp/www
>cd /tmp/www
>echo "Not Google :)" > index.html
>sudo python3 -m http.server 80
>```
>![[../images/04/dns_spoof_kali_http.png|Kali HTTP Server|600]]
>In another terminal, I switch to the root user, set the ip_forward flag to "1" to allow my Kali machine to forward packets and then setup an arpspoof targeting the Windows IP address and with the Ubuntu DNS server.
>```
>sudo su -
>echo 1 > /proc/sys/net/ipv4/ip_forward
>arpspoof -i eth0 -t 192.168.4.168 192.168.4.169
>```
>![[../images/04/dns_spoof_arp_spoof_1.png|Kali ARP Spoof Windows|600]]
>With Kali now poisoning the Windows VM, I'll open another window and poison the target Ubuntu DNS server and Windows IP.
>```
>sudo arpspoof -i eth0 -t 192.168.4.169 192.168.4.168
>```
>![[../images/04/dns_spoof_arp_spoof_2.png|Kali ARP Spoof Ubuntu|600]]
>Now the Kali is poisoning both the Ubuntu and Windows VMs, convincing each that Kali is the other, and a malicious web server is running, I can finally setup the malicious DNS server on Kali.  First I setup a dns.txt file with an entry with the Kali eth0 IP address for www.google.com.  Then I run the dnsspoof command on the interface eth0 referencing the dns.txt file.
>```
>echo "192.168.4.167 www.google.com" > dns.txt
>sudo dnsspoof -i eth0 -f dns.txt
>```
>![[../images/04/dns_spoof_kali_dnsspoof.png|Kali DNS Spoof Running|600]]
>I now have 4 terminals running: 2 with arpspoof, 1 with an HTTP server, and 1 with dnsspoof.  The attack is fully staged, the last thing to do is intice the victim to navigate to www.google.com.  The victim will first conduct a DNS query which will be highjacked because of the ARP poisoning.  Our malicious DNS server will resolve the requested address with our attacker IP address.  Finally our Kali machine will server the malicious Google site.  From the Windows VM, I open a private browser window, to avoid any caching, and navigate to http://www.google.com.
>![[../images/04/dns_spoof_trigger.png|Windows Victim Served Malicious Google Page|400]]
>The victim is served the malicious page!  Going back to Kali we can see the DNS spoof logs are resolving the request made by the victim.
>![[../images/04/dns_spoof_kali_spoof_logs.png|Kali DNS Spoof Logs|600]]
>While on the Kali VM we can see the HTTP logs serving the victim the malicious web site.
>![[../images/04/dns_spoof_http_logs.png|Kali HTTP Logs|600]]

> [!exercise] Exercise - DNS Spoofing
> The DNS Spoofing task will use the Ubuntu VM as a DNS server, the Windows VM as a DNS client, and the Kali VM as a malicious DNS server. The goal will be to get the Windows VM to resolve IP addresses from the Kali VM in a static network. Setup each VMs’ (Ubuntu, Windows, Kali) network settings to `Bridged Adapter` mode. 
> #### Step 1 - Setup DNS Server
> From the Ubuntu VM, install and configure the DNS server (using dnsspoof).  Within the Ubuntu terminal, modify your primary user account to use sudo. Make sure to replace `USER` with your username on the VM. 
> ```
> su -  
> usermod –aG sudo USER
> ```
> Reboot the VM for the sudo settings to take effect. Once rebooted, you will be able to run commands as the root user from your primary user account.  Next, install dsniff using the following command.  
> ```
> sudo apt install dsniff –y 
> ```
> After dsniff has been installed, lookup the IP address of google.com to be used in a dns.txt file. Make sure to replace the `IP` with the IP address of google.com. 
> ```
> nslookup google.com 
> echo “IP google.com” > dns.txt 
> ```
> Identify the network interface of your Ubuntu VM by running the following command. It might be something like “enp0s3”. 
> ```
> ip a 
> ```
> With dsniff installed, the dns.txt file created, and the network interface identified, start the dnsspoof server. Make sure to replace `INTERFACE` with the network interface identified in the last command. 
> ```
> sudo dnsspoof -I INTERFACE -f dns.txt
> ```
> #### Step 2 - Configure Windows DNS Setting
> In this step you will modify the Windows interface DNS settings to use the Ubuntu VM.  From the Windows VM, right-click the network tray icon and select “Open Network & Internet settings”. Select “Change adapter options” in the main pane under “Advanced network settings” section. Right-click “Ethernet” and select “Properties” to launch the interface property window. With the interface properties window opened, select “Internet Protocol Version 4 (TCP/IPv4)” and press the “Properties” button. Select the “Use the following DNS server addresses:” radio button and enter the IP address of the Ubuntu VM.  Press “Ok” and close out the windows that were opened for the network settings. 
> ![[../images/04/dns_win_settings.png|Windows DNS Configuration]]
> You should see log activity in the Ubuntu dnsspoof terminal when running the following command from a Windows command prompt. 
> ```
> nslookup google.com
> ```
> #### Step 3 - Spoof DNS
> With the Ubuntu DNS server running, and the Windows VM configured to use the Ubuntu DNS resolver, launch a MitM + DNS Spoof attack from the Kali VM. Launch a terminal in the Kali VM and install dsniff. 
> ```
> sudo apt install dsniff -y 
> ```
> Identify the IP address of the Kali VM and add it to a dns.txt file for google.com. Make sure to replace `IP` with the IP address of the Kali VM. 
> ```
> ip a 
> echo “IP google.com” > dns.txt 
> ```
> Configure the Kali VM to forward IP addresses that will be used in the MitM attack. You will switch the user to root, set the process ip_forward flag to 1, and exit the root terminal. 
> ```
> sudo su - 
> echo 1 > /proc/sys/net/ipv4/ip_forward 
> exit
> ```
> With the Kali VM set to forward IP addresses, and while in a user terminal (not root), spoof the arp resolution between the Windows to Ubuntu VMs. Make sure to replace the `WIN_IP` with the IP address of the Windows VM and the `UBUNTU_IP` with the IP address of the Ubuntu VM. 
> ```
> arpspoof -t WIN_IP UBUNTU_IP
> ```
> With Windows and Ubuntu traffic being spoofed, launch another Kali terminal and spoof the traffic between the Ubuntu and Windows VMs (opposite traffic flow from the last command). Make sure to replace the `WIN_IP` and the `UBUNTU_IP` IP addresses with the respective VM IP addresses. 
> ```
> arpspoof -t UBUNTU_IP WIN_IP
> ```
> You should have two Kali terminals opened and each spoofing traffic between the Ubuntu and Windows VMs. Next, open a third terminal and identify the network interface of the Kali VM (might be eth0). 
> ```
> ip a 
> ```
> Within the third terminal opened and the Kali interface identified, launch the dnsspoof attack. Make sure to replace the `INTERFACE` in the command with the name of the interface identified in the previous command. 
> ```
> sudo dnsspoof -I INTERFACE -f dns.txt
> ```
> #### Step 4 - Trigger Attack
> With the Kali VM spoofing traffic between the Windows and Ubuntu VMs, we are ready to observe the results of the attack.  If successful, we should observe that google.com now resolves to the Kali VM. From the Windows VM terminal, lookup the IP address of google.com 
> ```
> nslookup google.com
> ```
> You should observe that google.com resolves to the Kali VM.  If not, consider the following: 
> - Review your configurations 
> - Flush local DNS cache in the Windows VM with the following command: ipconfig /flushdns 
> - Wait a few minutes and try again 
> #### Step 5 - Decommission
> After you have completed the lab, make sure to revert changes made to your Windows VM.  Consider restoring from a previous snapshot or manually turning the Firewall profiles on and removing the manual DNS server IP address on the Ethernet interface. 
## Dynamic Host Configuration Protocol (DHCP)
As previously discussed, NICs have their MAC addresses burned in during the manufacturing process.  However, IP addresses assignment works quite differently and are assigned by **dynamic host configuration protocol (DHCP)** servers, often found within routers or as stand alone servers.  DHCP is responsible for assigning IP addresses to LAN hosts and can be configured to provide ranges or specify which MAC gets a static IP address.  The DHCP server keeps a table of each networked device's MAC, assigned or leased IP address, and an expiration of the lease.  When an IP address lease expires a new one will be reassigned or perhaps the same IP address will be renewed.  The client device receiving the IP address then validates that IP address over ARP to avoid collisions in IP use and assignment.
![[../images/04/dhcp_basic.png|DHCP Lease|250]]

### DORA

When a device joins the network it won't have an IP address until one is negotiated with the DHCP server.  One of the first actions a new device does is broadcast to all devices on the network a message inquiring who is the DHCP server, called *discover*.  The DHCP server, along with all other devices, responds to the discover request with an *offer* of an IP address for the new device to use.  The new device considers this offer, and if appropriate, sends a *request* to the DHCP server asking to use the offered IP.  The DHCP server gets this request and adds an entry in the DHCP IP assignment table with that new device's MAC, IP and expiration.  Afterwards the DHCP server sends the final *acknowledge* packet to the new device so it can register the IP address in its network stack.  The entire process of discover, offer, request, and acknowledge is referred to as **DORA**. 
![[../images/04/dhcp_dora.png|DHCP DORA Traffic|400]]


The figure above demonstrates the order and directionality of the DORA communications between a server and client.  Healthy network devices that receive discover requests simply ignore them.  But any network device could respond claiming they are the DHCP server
### DCHP Release
Another interesting request from a client to a DHCP server is the **release** packet.  The subject device will notify the server if it no longer needs the currently assigned IP address.  This is helpful in circumstances where the client prefers another IP address, perhaps a network administrator will assign it a static IP address.  To affect this change the client sends the DHCP server the release packet and the server removes the existing MAC to IP binding in is IP table.  Misbehaving devices might spoof these requests causing the disassociation of IP addresses with target victims on the network.
### DHCP Risks
DHCP, like many other network protocols, inherently trust devices connected to the network.  This makes sense as one can assume that physically connected devices were placed onto the network with permission.  However, it is imaginable that an attacker could physically install a device on a network, connect via WiFi, or even compromise an existing and already connected device.  Understanding that threats could reach networks leave DHCP vulnerable to at least two classes of risk.  

Should the DHCP server become unavailable the network would immediately begin to decay and IP addresses expire.  Dynamic networks with devices being added and removed would quickly find they can't utilize network resources, like routing to the internet, and the entire system would eventually come to a halt.  Availability, of the CIA triad, is the concern here and attackers could wage attacks that threaten the DHCP service for its clients.  We'll examine a type of DHCP DoS attack in the next section.

Another threat is hijacking the DHCP server which compromises the integrity and can lead to the compromise of confidentiality of systems on  the network.  Because there is no default way to validate DHCP clients and servers on the network, there may not be much to prevent an attacker from impersonating or acting as the DHCP server.  The impact of this weakness enables a malicious actor from assigning itself as a default gateway and control network traffic.
### DHCP Attacks
In the risks section, the idea of a DoS threat was mentioned that could impact the availability of the DHCP service on a network.  There are at least a few methods that could achieve this but one interesting attack that involves using the DHCP service and exploit how it functions.  A **DHCP starvation** attack attempts to exhaust the available IP addresses for a network by consuming the entire range of available addresses.  The attacker repeatedly sends requests to the DHCP server for addresses until the entire subnet range is used.  This has the effect of blocking any existing devices from renewing and blocks new devices from procuring an address.  Eventually all devices lose their IP addresses effectively shutting out of the network.  The following diagram depicts a DHCP starvation attack by an attacker while illustrating a client from obtaining an IP address.
![[../images/04/dhcp_starvation.png|DHCP Starvation Attack|300]]
An attacker could launch a **DHCP spoofing** attack with the goal of assigning itself as the network's default gateway.  If the attacker can get the DHCP server and clients to assign and use the attacker's IP as the gateway, the attacker can inspect and manipulate all traffic in the network.  This attack works by the attacker impostering as the DHCP server and responding to requests on the network.  As demonstrated in the figure below, these responses include the assignment of the default gateway to the attacker's IP address.  The victim then sends their outbound traffic to the attacker instead of the network's gateway!
![[../images/04/dhcp_spoofing.png|DHCP Spoofing Attack|300]]

>[!activity] Activity - DHCP Spoofing Attack
>I'll demonstrate a DHCP spoofing attack using Ettercap which provides a nice GUI to perform and manage several networking attacks.  The Windows VM will act as my victim and I'll launch the attack from the Kali VM, both using the `Bridge Adapater` network modes.
>
> For sake of the demonstration, I need to know the Windows VM's IP address and the gateway of the network.  This could be determined using NMAP or another host discovery tool.  I launch a command prompt and run ipconfig to view the needed network details of the victim.  It is on the 192.168.4.0/24 network, has the IP address 192.168.4.168, and shows the default gateway as 192.168.4.1.
> ```
> ipconfig
> ```
> ![[../images/04/dhcp_activity_win_net.png|Windows VM Network Settings|600]]
> Switching to the Kali machine I run similar commands and confirm it is on the same network as the Windows VM (192.168.4.0/24).
> ```
> ip a
> ```
> ![[../images/04/dhcp_activity_kali_net.png|Kali VM Network Settings|600]]While still on the Kali machine, I launch Ettercap as root using sudo and with the `-G` option to use the GUI.
> ```
> sudo ettercap -G
> ```
> ![[../images/04/dhcp_activity_ettercap.png|Ettercap GUI Homescreen]]
> The first step is to start Ettercap's sniffing utility on the interface from the network our victim is on which is eth0.  Sniffing is started by pressing the checkmark button in the upper right corner of the application next to the ellipsis button.
> ![[../images/04/dhcp_activity_sniffing.png|Ettercap Sniffing Mode]]
> Once sniffing is initiated the log pane appears at the bottom of the screen detailing the configuration and confirmation that Ettercap has started sniffing traffic.  Soon we will start seeing logs of packets being captured!  A few new buttons appear at the top of the Ettercap application including a menu represented by a globe next to where the sniffing/checkmark button was.  I can stop the network sniffing by pressing the stop button in the upper left corner.  However, I'll leave sniffing enabled during this attack.  To configure the attack, I press the globe icon and then DHCP Spoofing.
> ![[../images/04/dhcp_activity_globe.png|Ettercap Attack Menu Options|350]]
> After pressing the DHCP spoofing option of the menu a dialog box pops up needing information for the attack.  I enter the victim Windows IP address in the "IP range", the network's subnet mask, and I put the IP address of Kali in the DNS server field.  These settings will instruct Ettercap to target the Windows machine and poison it's network settings to think the Kali machine is the DNS server.
> ![[../images/04/dhcp_activity_config.png|DHCP Spoof Configuration|300]]
> Once the settings are entered in to the fields I press Ok which starts the attack.  Eventually the Windows VM will change its network gateway to the Kali machine.  To speed this along I'll renew the Windows IP address forcefully to imitate an IP lease that expires.
> ```
> ipconfig /release
> ipconfig /renew
> ```
> ![[../images/04/dhcp_activity_renew.png|Windows IP Release and Renewal|600]]
> The default gateway now shows as 192.168.4.167 which is the Kali VM!  Going back to Kali's Ettercap application I can see DORA packets showing in the log pane.
> ![[../images/04/dhcp_activity_logs.png|DORA Packets in Ettercap Logs]]
> At this point any Windows traffic will be routed through the Kali machine!
> 


> [!exercise] Exercise - DHCP Spoofing
> This task will use the Windows and Kali VMs in network Bridge Adapter mode. The Kali VM will spoof DHCP using Ettercap and if successful, the Windows VM’s gateway IP will show the Kali VM IP address. 
> #### Step 1 - Observe Victim Gateway
> From the Windows VM command prompt, observe the IP and gateway addresses in the network settings using the following command. 
> ```
> ipconfig
> ```
> #### Step 2 - DHCP Spoof Attack
> Run the DHCP Spoof attack from the Kali VM with the Windows machine as the victim.  From a Kali VM terminal, observe the netmask and IP address using the following command. 
> ```
> ip a
> ```
> Launch Ettercap from the Kali VM terminal. 
> ```
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
### DHCP Security
Switches can mitigate the DHCP starvation and snooping attacks through built in security features.  With DHCP starvation attacks the actor sends multiple requests to the DHCP server with different MAC addresses requesting issuance of IP addresses.  These requests traverse the network switch sending the packets to the DHCP server.  Many managed network switches have a security setting call **port security** which is applied to each interface, or port, of the switch.  Port security can be set to allow a certain number of MAC addresses per interface.  If the number of MAC addresses associated with the interface exceeds the port security limit, then the switch will disable the interface blocking any further traffic.  Port security thresholds can be set to one or more MAC addresses allowed, usually the first address of the port.  A network administrator would then need to purposefully reopen the interface to allow traffic to flow again.  This security setting mitigates several network attacks including the DHCP starvation attack as it will shut the misbehaving interface down early in the attack as demonstrated in the figure below.

![[../images/04/dhcp_port_security.png|Port Security|400]]


The other type of attack we covered is the DHCP spoofing attack and the rouge DHCP server attacks.  In these attacks the actor seeks to convince device on the network that it is the gateway to the network which empowers the attacker to inspect and manipulate traffic on the network.  These attacks can be mitigated through the use of another managed network switch security setting called **DCHP snooping**.  This setting defines the interface on the switch which the DHCP server resides on.  Any DHCP response packets not generating from this interface will be dropped by the switch.  If an attacker claims to be the DHCP server from an interface that is not statically assigned, its packets will be dropped thus preventing the attacker from achieving their objective.

![[../images/04/dhcp_snooping.png|DHCP Snooping|450]]

## TCP
We have already covered the basics of TCP in the last chapter.  You may recall the introduction of the three-way hand shake where a client sends a SYN packet to the server, the server responds with a SYN+ACK, and the client finally sends an ACK packet before starting the transmission of data.  TCP is heavily used in networking with most popular protocols relying on it as the resilient means to communicate.

Another packet sent by the client to the server is the **reset (RST)** packet which terminates a connection stream.  You can see this packet ending a transmission in the figure below.
![[../images/04/tcp_rst.png|TCP Reset Packet|250]]
The RST packet is used to notify the server that the client no longer intends to send data and the server can end the connection in its network stack.  If a client needs to transmit data thereafter, it is required to reestablish a connection by engaging in the three-way handshake once again.

### TCP Threats
TCP, which resides in layer 4 of the OSI model, is subject to attacks with effects similar to other networking protocols.  Its placement in the middle of the network stack encapsulating so many other protocols makes it a prime target.  Disrupting TCP can causes  higher order protocols, such as HTTP, to also fail.  Therefore, maintaining a server's ability to maintain TCP connections is crucial for the security, or availability, of the service.  This makes TCP a candidate for *denial of service (DoS)* attacks in which the attacker hopes to disrupt the flow of TCP wrapped packets.  

Every TCP connection starts with a client SYN packet and then a server SYN+ACK response.  A misbehaving client can send repeated SYN packets causing the server to open a connection for each one.  These open connections eventually expire but if a client, or group of misbehaving client, sends many requests at once it can quickly fill the TCP connection capacity of the server and block legitimate clients from establishing connections in a **TCP SYN flood** attack as illustrated below.
![[../images/04/tcp_flood_attack.png|TCP Flood Attack|500]]

> [!activity] Activity - TCP SYN Flood Attack
> I'll demonstrate such an attack from the Kali VM against the Ubuntu VM acting as the server.  Using the `Bridge Adpater` settings on each VM, I'll configure the Ubuntu machine to serve HTTP traffic, a TCP protocol, and launch a **TCP SYN flood** attack on it.
> 
> After launching Ubuntu and opening a terminal, I start a simple HTTP server over port 80 using a Python built-in module.  Once the server is started, it sits idle waiting for incoming connections.
> ```
> sudo python3 -m http.server 80
> ```
> ![[../images/04/activity_flood_http_server.png|Ubuntu Python HTTP Server|600]]
> The next steps will require knowning the IP address and network interface.  Using a terminal I run the ip command to identify this information.  I see the interface is enp0s3 and the IP address of the Ubuntu machine is 192.168.4.169.
> ```
> ip a
> ```
> ![[../images/04/activity_flood_ubuntu_net.png|Ubuntu Network Settings|600]]
> I want to be able to observe the TCP connections made on the server so I'll use Tcpdump on the primary network interface and filter requests for incoming port 80 requests.  The `-n` ensures only IP addresses are displayed and not host names while `-vvv` gives us a very verbose output.  Upon entering the command the Tcpdump application runs awaiting incoming connections to be captured.
> ```
> sudo tcpdump -i enp0s3 port 80 -n -vvv
> ```
> ![[../images/04/activity_flood_tcpdump_start.png|Tcpdump Started on Ubuntu|600]]On the Kali machine I can test access to the HTTP server using the Curl utility in a terminal.  After running this command I observe that the HTTP server responds with a directory listing page.
> ```
> curl 192.168.4.169
> ```
> ![[../images/04/activity_flood_kali_curl.png|Kali Curling Ubuntu Web Server|600]]
> With the successful Curl request from Kali I observe that both the HTTP Python and the Tcpdump windows log the requests!
> ![[../images/04/activity_flood_logs.png|Ubuntu Success Logs]]
> The server, or victim, and client, or attacker, are configured correctly so I'm ready to launch the attack.  I will use the Hping3 tool to start a TCP flood attack on the server.  The `-c` command is the number of packets to be sent, the `-d` command is the byte size of each packet, the `-S` option specifies the SYN flag, and finally the `-w` options specifies the window size.  Once the command is ran it will repeatedly and quickly send SYN packet after SYN packet opening connections on the Ubuntu server.
> ```
> sudo hping3 -c 15000 -d 120 -S -w 64 -p 80 --flood --rand-source 192.168.4.169
> ```
> ![[../images/04/activity_flood_attack.png|Hping Flood Attack from Kali|600]]
> The output of hping suggests it won't show any replies.  Jumping over to the Ubuntu server and watching the Tcpdump output I can see many new log entries coming in fast succession!
> ![[../images/04/activity_flood_attack_logs.png|TCP Flood Attack Streaming Logs|600]]

TCP does not utilize encryption which leaves all of its wrapper information exposed in cleartext.  However, TCP's data payload include higher order data that may be encrypted.  TCP connections can also be hijacked by attackers enabling them to take control of the connection such as the previously demonstrated *man in the middle (MitM)* attacks.  Without sufficient mitigating controls, an attacker can launch a **TCP reset attack** that will cause the client-server connection to terminate.  This attack requires the attacker to know the sequence number and sockets of the victim's connection, which can be obtained through brute force or packet sniffing. 
![[../images/04/tcp_reset_attack.png|TCP Reset Attack|300]]

>[!activity] Activity - TCP Reset Attack
>To demonstrate a TCP reset attack, I'll use just the Kali VM on `Bridge Adapter` network mode.  The Kali machine will serve as both the client and the server using Netcat.  With Wireshark capturing packets, I'll establish a connection between the client and server and obtain details about the connection.  This information will enable the attack using Netwox to send a RST packet and break the client-server connection.
>
>First I'll start Wireshark through the applications menu and select the Loopback interface.  Double clicking this interface starts a packet capture.
>![[../images/04/activity_rst_wireshark_start.png|Kali Starting Wireshark on Loopback Interface]]
>With the packet capture running, I next need to setup the client and the server.  Starting with the server, I launch a terminal and use Netcat to listen on port 8000 for incoming connections with verbose output and keeping the connection alive.
>```
>nc -nvlp 8000
>```
>![[../images/04/activity_rst_server.png|Netcat Server Port 8000|600]]
>Launching another terminal (2nd), I use Netcat to establish a connection to the server listening on port 8000.  I use the home address 127.0.0.1 to make this local connection and then send a message `hello!` by typing into the connection.  The connection remains open ready to take additional data, and does not return us to the bash terminal.
>```
>nc 127.0.0.1 8000
>```
>![[../images/04/activity_rst_hello.png|Client Connection to Netcat Server 8000|600]]
>Immediately I can observe that the server accepts the connection and displays the client's incoming message.  The output also shows the client port 34502 that the connection came from.
>![[../images/04/activity_rst_connection.png|Incomming Connection from Client|600]]
>The client and server terminals and connection examples a normal TCP communication channel.  This connection will be the target of my attack.  As the attacker, I had a Wireshark packet capture running on the loopback interface which should have collected the client server connection.  Within Wireshark, I select the last TCP ACK packet and expand the TCP header to identify the `Sequence Number (raw)` value 2032347291 which I'll use to send a RST and disrupt the client - server connection.
>![[../images/04/activity_rst_sequence_number.png|Sequence Number (raw) Identified in Wireshark]]
>I'll use the tool Netwox to run this attack in a new terminal.  Netwox isn't preinstalled in Kali so I install it using the following command.
>```
>sudo apt install netwox -y
>```
>![[../images/04/activity_rst_netwox_install.png|Installing Netwox|600]]
>With Netwox installed, the sequence number captured, and the client and server sockets known, I am ready to break the connection.  Using Netwox configure it to point to the sockets and target the sequence number of the last ACK packet.  Upon running the command I get an output of the TCP/IP packet that was sent.
>```
>sudo netwox 40 -l 127.0.0.1 -m 127.0.0.1 -o 8000 -p 34502 -B -q 2032347291
>```
>![[../images/04/activity_rst_netwox_attack.png|Netwox Attack on Connection|600]]
>Wireshark captures the RST packet sent by Netwox.
>![[../images/04/activity_rst_attack_capture.png|Wireshark RST Packet Captured]]
>Pulling up the client window shows that the connection terminated since the client is returned to the bash prompt!
>![[../images/04/activity_rst_closed.png|Client Connection Terminated|600]]
>
>

### TCP Security
There are several security measures that can be used to mitigate the threats to TCP.  A server's network setting TCP backlog threshold can be increased from its default setting.  The backlog limits the number of outstanding three-way handshakes that are incomplete.  Because the protocol requires back and for communication and the client initiates the connection, it could take some time for the client to send the ACK packet, if ever.  The server's configurations will determine how many pending TCP connections are allowed at once, and once full won't make any additional connections.  Therefore, increasing the number of these backlog connections gives the server more capacity to handle an attack.  The backlog threshold does have an upper limit of what it can handle depending on the system's resources to this mitigation won't completely solve a flood attack.  For internet connected services could leverage proxy or upstream internet service providers security and capability to absorb backlogs of TCP connections.  CloudFlare offers a popular proxying service that fronts an HTTP service and has a great amount of capacity to prevent TCP flood attacks. 

The risk of TCP reset attacks can be mitigated through the use of cookies, sometime referred to as canaries.  In this context a cookie is used as a special indication of a client and server connection allowing the  server to authenticate the incoming TCP packet with the trusted client.  The **SYN cookie** is a server side control that encodes the client information into a string value, called a cookie.  The cookie value is stored in a table server side for each connection and should any incoming TCP packets not match the client's cookie the packet is dropped.  

Another cookie method, the **RST cookie**, mitigates  attacks by validating clients beforehand.  In this strategy the server sends an invalid SYN+ACK packet to the client after receiving the initial connection and logs the transaction.  The server won't open any new TCP connections from the client until the client sends a RST packet in response to the server's invalid SYN+ACK request.  Once the client does send the RST packet, the server assumes the client is responsible and adds it to an allow list server side foregoing any additional RST cookie procedures for that client.


> [!exercise] Exercise - TCP Reset Attack
> You will perform a TCP reset attack against a local client and server in this task.  Use the Kali VM with the `Bridge Adapter` network setting.
> #### Step 1 - Install Netwox
> From a Kali terminal, install Netwox using the following command.
> ```
> sudo apt install netwox -y
> ```
> #### Step 2 - Launch Wireshark
> From the Kali applications menu, launch an instance of Wireshark.  Select teh `Loopback:lo` interface and start a packet capture (blue fin icon in the upper left).
> #### Step 3 - Setup the Server and Client
> Launch a new terminal and switch the user to root.  Then start a Netcat server listening on port 8000.
> ```
> sudo su -
> nc -nvlp 8000
> ```
> Launch another terminal and establish a connection to the server just created.  Once connected, type your name and observe the server's standard output in the server terminal.
> ```
> nc 127.0.0.1 8000
> YOUR_NAME
> ```
> Observe the open TCP connection port in the server window.  This port number will be needed in the next steps.
> #### Step 4 - Observe the Sequence Number
> Return to Wireshark and select the last ACK packet.  Find the packet’s raw Sequence Number (should be about 10 digits).  Find your sequence number as it will be needed in the following steps.
> #### Step 5 - Launch the Reset Attack
> Open a 3rd terminal and run the following command.  Make sure to change the `CLIENT_PORT` and `RAW_SEQ_NUM` to the values you found in the previous steps.
> ```
> sudo netwox 40 -l 127.0.0.1 -m 127.0.0.1 -o 8000 -p CLIENT_PORT -B -q RAW_SEQ_NUM
> ```
> Return to the terminal that has the client running and confirm the connection was disconnected.  You should see a return to the shell and that you can no longer enter text that the server receives.
## Wireless
The development of **wireless fidelity (Wi-Fi)** expanded networks beyond the confines of physical connection enabling networks to be formed over radio signals.  The convience gained for devices to be connected to an internal network and the internet without the direct connection of Ethernet cables increases user experience and promotes flexability in device use.  For instance, companies use this technology to enable operations introducing mobile technologies like laptops, tables, and smart phones.  
![[../images/04/wifi_network.png|Basic Wireless LAN Network|400]]
The IEEE 802.11 standards are the basis for **wireless LAN (WLAN)** which connect devices wirelessly to a *wireless router* or *access point*.  The access point is does have a wired connection to the network's switch and router making it another router on the network.  These WLANs can be part of the existing LAN or extend as a new LAN depending on the configuration.  The figure above illustrates a simple network of wireless devices connected to a physical LAN.  At the time of this writing, wireless network standards have been around several decades starting in the early 90s and a have evolved over many versions known as *generations*.  Each generation has some improvement over previous generations allowing for increased speeds or bandwidth over 2.4, 5, or 6 GHz frequencies.  The higher the frequency the more bandwidth as the peaks and troughs of the signal are tighter together packing in more data; however, the cost of higher frequencies is its range as they have less distance an object penetration ability, such as through walls.  Each generation is usually referred to by its IEEE standard with the latest iteration of 802.11 on *"be"*.  The table below from Wikipedia outlines all generations, their speeds, and radio frequencies. [^1]
![[../images/04/wifi_gens.png|Wikipedia WiFi Generations|400]]

The name of wireless networks are known as **service set identifiers (SSID)** and are what you may be familiar with while connecting to a wireless network.  The SSID is the name that appears when a device scans the area for available networks to connect to.  A **basic service set identifier (BSSID)** is the MAC address of the wireless router or access point.  Some wireless networks can include multiple access points while being on the same network.  Each access point has to be distinguishable from one another using the BSSID. 

Wireless networks can be established under two service classes **basic service set (BSS)** and **extended service set (ESS)**.  At its simplest, a peer to peer network could be formed by connecting two devices without a wireless router in an **independent BSS (IBSS)**.  Here network is formed by direct connections without a wireless router or access point while still forming an SSID.
![[../images/04/wifi_ibss.png|Independent Basic Service Set (IBSS)|200]]
Your home wireless network is likely an **infrastructure basic service set** where devices connect to a single wireless router that is connected to the physical network router.  In this service, the entire network creates a basic service set and the wireless router adversities its SSID and has a unique BSSID.  
![[../images/04/wifi_infra_bss.png|Infrastructure Basic Service Set|250]]
Mentioned earlier, ESS networks have multiple wireless access points with unique BSSIDs and connected back to a single physical network router.  Collectively this network forms an ESS under a single SSID where any device can connect to any BSS router and be on the same network.
![[../images/04/wifi_ess.png|Extended Service Set (ESS)|250]]
ESS networks can usually be found in larger complexes where a single access point does not provide adequate coverage of the entire area needing wireless access to the network.  
### Wi-Fi Security
The most obvious concern with wireless networks is unauthorized access.  Traditional physical networks mitigate rouge devices access the network with physical security.  Network administrators could rely, at least in part, on the fact that a device could only connect to the network requiring entering the premises traversing walls, doors, receptions, and go unnoticed by employees.  It is conceivable that an individual could smuggle a device and connect it onto the physical network at demarcation points or within the office, but the physical security measures provide some control.  Most of these physical security controls go out the window, literally, with wireless networks as the radio frequencies leak outside the protected physical space.  Anyone can detect and capture wireless signals emitting from a building even from a distance using high powered directional antennas.  Once an attacker is able to access the network wirelessly, all the traditional network attacks we have learned about, and more, apply.

This was fact was realized early in the development in the technology and several versions of security were implemented overtime.  Early security standards were found to have critical weaknesses making the deprecated in favor of more modern and secure versions.  But they each share common characteristics of authentication and encryption to control access to a network.  A user must first authenticate to the network and all radio transmissions carrying network packets are wrapped in a layer of encryption.  Strong passwords, secure encryption algorithms, and proper key handling become essential for the security of the network.  The following table summarizes the wireless encryption standards with WPA3 being the current and recommended standards.

| Standard | Description | Security |
| ---- | ---- | ---- |
| Wired Equivalent Privacy (WEP) | Original standard encrypting all data with a single short key. | Obsolete |
| Wi-Fi Protected Access (WPA) | Replacement for WEP using temporal key integrity protocol (TKIP) which is now deprecated in favor of AES. | Poor |
| Wi-Fi Protected Access 2 (WPA2) | Supersedes WPA offering pre-shared keys and advanced counter mode cipher block (CMMP) chaining AES encryption. | Good |
| Wi-Fi Protected Access 3 (WPA3) | Modern standard using enhanced cipher modes, secure handshakes, and brute force protections. | Great |

Other types of protections wireless network administrators can deploy include MAC filtering, only allowing known devices to connect, tuning radio frequency power to limit the signal from leaking beyond the property, and advanced networks can be tied into intrusion detection systems (IDS) to detect and alert upon threats.

### Wi-Fi Attacks
The threat of a man in the middle (MitM) attack is prominent in a wireless network and is mostly mitigated through good encryption.  However, if the encryption is broken or implemented poorly it opens the network to the attacker.  There are however other techniques and attacker can use to intercept victim's traffic.  A classic example of this is the **evil twin** attack were the attacker setups up a wireless access point with a similarly named SSID in an attempt to trick victims to connect to them.
![[../images/04/wifi_evil_twin.png|Evil Twin Attack|300]]
In the evil twin attack depicted above, the attacker sets up a wireless router they control with a name similarly sounding to the exiting network.  Notice the slight name change using the number zero in place of the letter "o".  Perhaps the attacker could name the SSID something just as enticing like "FreeWi-Fi" and likely get connections in a crowded coffee shop.  If the attacker controls the router they will decrypt any transmissions from victims.  Like other MitM attacks we've explored, they can forward traffic to its intended destination and manipulate packets without the victim knowing.

Organizations must also concerns themselves with **rouge access points** where an attacker, or an unwitting employee, connects a wireless router to the physical network.  Once connected to the physical network, the wireless router is given an IP address and devices can connect to the network wirelessly.
![[../images/04/wifi_rouge.png|Rouge Access Points|300]]
Not only can rouge access points cause network routing issues for network administrators but they extend the network beyond the confines of the physical network.  It can enable an attacker to reach the otherwise unreachable network providing remote access to wage additional attacks.  Good network security, like MAC filtering or port security, could prevent this attack.

Access to the wireless network can be jammed using radio emitting devices designed to cancel the radio wave lengths preventing any user for connecting or maintaining connections.  Such jamming devices are available on Amazon for as little as $100.  Another wireless denial of service (DoS) attack is to simply boot a victim off the wireless network using the native *deauthentication* request.  This **deauth** attack leverages the 802.11 standard to notify the access point that the device is disconnecting.  An attacker only need be connected to the same wireless network and know the MAC address of the victim to send, and repeatedly send, deauth requests booting the victim and keeping them off the network.
![[../images/04/wifi_deauth.png|Deauth Attack on Wireless Network|400]]

Deauth attacks can be a component of a additional attacks where the attacker attempts to record a victim's key exchange with a wireless router.  The attacker will boot the victim off the network while having a wireless packet capture running.  When the victim attempts to reconnect to the wireless router they must perform a key exchange to set up a secure connection.  The attacker collects the key exchange packets that can then be used to perform cryptanalysis and break the encryption.  The type of attack is what makes WPA insecure as the TKIP protocol is vulnerable to cracking.

![[../images/04/wifi_key_exchange.png|Wi-Fi Key Exchange Packet Capture|250]]

>[!activity] Activity - WiFi WEP Cracking
>The wired equivalent privacy (WEP) standard is insecure as it repeats a short, 24-bit, initialization vector (IV), or key, that repeats itself after 5k packets which is used to encrypt the traffic.  An attacker that captures several thousand packets has a high likelihood of cracking the encryption key used in WEP.  Once cracked, the key can be used to decrypt other packets that are captured allowing for the inspection and manipulation of WiFi traffic between the victim and the access point.  I'll demonstrate the security weakness WEP WiFi encryption is by using Aircrack to brute-force the IV from the captured traffic and WiFi packets in a subject capture.
>
>Capturing WiFi packets only requires a wireless NIC and for this demonstration I'll start by uploading the "kansascityWEP.pcap" file to my Kali VM to supplement the packet capturing process.  Kali already has the Aircrack tool installed and can be passed the PCAP file to being the key bruteforcing process.  After copying the PCAP to the VM's desktop, I open a terminal and begin the cracking process.
>```
>aircrack-ng ./Desktop/kansascityWEP.pcap
>```
>![[../images/04/activity_wep_aircrack.png|Cracking PCAP with Aircrack|600]]
>After the command runs, Aircrack analyzes the file idenfitying the WiFi networks within it along with statistic information.  After just a moment, the tool returns the hexadecimal key 1F:1F:1F:1F:1F that it was able to crack.
>![[../images/04/activity_wep_cracked.png|Cracked WEP Key|600]]
>With the key in hand we can open the PCAP within Wireshark by launching it through the Kali application menu.  Once launched, I navigate to File, select the Open option, and choose the kansascityWEP.pcap file that was uploaded to the desktop.  Exploring the packets without decrypting displays only wireless packets that when examined are found to have scrambled encrypted data.  We can't even tell the types of protocols being used.
>![[../images/04/activity_wep_packets_enc.png|Encrypted WEP Packets]]
>To view the packets in an decrypted form, I must add the encryption key that was recovered using Aircrack.  To do this I first enable the Wireless Toolbar that is under the View menu of Wireshark.
>![[../images/04/activity_wep_toolbar.png|Enable Wireless Toolbar in Wireshark|500]]
>Enabling the toolbar adds an additional row to our tool menu just above the packet listing pane in Wireshark.  To the right of the bar is a new button labeled 802.11 Preferences.
>![[../images/04/activity_wep_pref.png|802.11 Preferences Button on Toolbar|600]]
>Pressing the button opens the Preferences menu and auto-navigating to the IEEE 802.11 settings.  I select the `Enable decryption` checkbox and then press the Edit button next to the Decryption keys label so I can enter the key.
>![[../images/04/activity_wep_enable.png|802.11 Settings|600]]
>After pressing the Edit button the WEP and WPA Decryption Keys window pops up.  I press the `+` button to add a new key using the WEP for key type and entering 1F:1F:1F:1F:1F for the Key value.
>![[../images/04/activity_wep_key.png|Entering WEP Key Settings in Wireshark|500]]
>Once the key settings are in place, I press OK to close the WEP and WPA Decryption Keys window and then OK again to close the Preference window.  As soon as the Preference window is closed, Wireshark updates and decrypts all the packets.  I can now see each packet in plaintext observing several ARP packets!
>![[../images/04/activity_wep_decrypted.png|Decrypted WEP Packets|600]]
>

> [!exercise] Exercise - WiFi WEP Cracking
> Using the Kali VM with any network setting, you will download the accompanying file kansascityWEP.pcap, crack its WEP key, and decrypt the traffic.
> #### Step 1 - Crack the PCAP
> Download the kansascityWEP.pcap to the desktop of the Kali VM.  Note that you should be able to drag and drop files from your host machine to the VM.  If not, consider revisiting the Lab 1 Workstation Setup instructions or seek alternative file transfer methods. 
> 
> Launch a terminal and crack the WEP encryption using aircrack-ng and observe the cracked encryption key.  Make sure the terminal is in the directory of the pcap file or provide a full path in the following command. 
> ```
> aircrack-ng kansascityWEP.pcap
> ```
> #### Step 2 - Decrypt Traffic
> After cracking the encryption key, launch Wireshark from the applications menu.  Do not start a capture.
> 
> Open the kansascityWEP.pcap file in Wireshark.  Select File -> Open and then navigate to the file.  Once opened, you should see encrypted 802.11 packets loaded.  Enable the Wireless Toolbar under the View menu. 
> 
> Press the “802.11 Preferences” on the right side of the Wireless toolbar. This will launch the Preferences window.  Ensure that “Enable Decryption” is selected and then press the “Edit” button next to the Decryption keys label.  Press the “+” button and add the decryption key value in the Key field.  Press Ok and return to the main Wireshark window.
> 
> You should now see all traffic decrypted (ARP packets).

[^1]:Wi-Fi Generations Table; Wikipedia 2024; https://en.wikipedia.org/wiki/IEEE_802.11