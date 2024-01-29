# Attacking Network Services

images

intro

**Objectives**
1. Understand security of the address resolution protocol and how to attack it
2. Develop and understanding of the basics, security, and attacks against DNS
3. DHCP
4. Securing and attacking TCP 
5. Wireless systems.

## ARP
ARP Basics
### ARP Protocol
### ARP Cache/Table
> [!activity] Activity - ARP
### MiTM ARP Attacks
### Securing ARP
>[!activity] Activity - ARPSpoof

> [!exercise] Exercise - ARP Spoof Attack


## DNS
### DNS Infrastructure
### DNS Records
### Zone Transfer
>[!activity] Activity - Zone File

> [!exercise] Exercise - Zone Transfer File

### DNS Threats
- local cache poisoning
- remote cache poisoning
- malicious DNS server
- DNS Rebinding
- DNS Tunneling Exfiltration
- DNS Flood Attacks
>[!activity] Activity - DNS Spoofing

> [!exercise] Exercise - DNS Spoofing
## Dynamic Host Configuration Protocol (DHCP)
As previously discussed, NICs have their MAC addresses burned in during the manufacturing process.  However, IP addresses assignment works quite differently and are assigned by **dynamic host configuration protocol (DHCP)** servers, often found within routers or as stand alone servers.  DHCP is responsible for assigning IP addresses to LAN hosts and can be configured to provide ranges or specify which MAC gets a static IP address.  The DHCP server keeps a table of each networked device's MAC, assigned or leased IP address, and an expiration of the lease.  When an IP address lease expires a new one will be reassigned or perhaps the same IP address will be renewed.

When a device joins the network it won't have an IP address until one is negotiated with the DHCP server.  One of the first actions a new device does is broadcast to all devices on the network a message inquiring who is the DHCP server, called *discover*.  The DHCP server, along with all other devices, responds to the discover request with an *offer* of an IP address for the new device to use.  The new device considers this offer, and if appropriate, sends a *request* to the DHCP server asking to use the offered IP.  The DHCP server gets this request and adds an entry in the DHCP IP assignment table with that new device's MAC, IP and expiration.  Afterwards the DHCP server sends the final *acknowledge* packet to the new device so it can register the IP address in its network stack.  The entire process of discover, offer, request, and acknowledge is referred to as **DORA**. 

Healthy network devices that receive discover requests simply ignore them.  But any network device could respond claiming they are the DHCP server
### DCHP Release
### DHCP Risks
### DHCP Attacks
- DHCP Starvation
- DHCP Spoofing
>[!activity] Activity - DHCP Spoofing Attack

> [!exercise] Exercise - DHCP Spoofing
### DHCP Security
- DHCP Snooping
- Dynamic ARP Inspection (DAI)

## TCP
basics
### TCP Threats
### TCP Security
>[!activity] Activity - TCP Reset Attack

> [!exercise] Exercise - TCP Reset Attack
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

> [!exercise] Exercise - WiFi WEP Cracking