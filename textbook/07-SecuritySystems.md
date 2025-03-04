# Chapter 7 - Security Systems
![](../images/07/security_patch.jpg)

There are preventative and detective controls that security professionals can implement to protect the security of computer systems and networks.  Tooling often accompanies a control, where some technology or software is used to achieve a secure outcome.  The aim of some security solutions is to prevent the compromise of systems whereas other solutions attempt to detect when a compromise occurs.  This chapter starts with an overview of statistics by leading cybersecurity research groups that analyze industry trends on how organizations get compromised.  We will cover tooling and processes that focus on software vulnerabilities as well as the susceptibility of end users as these are the common system compromise vectors.  We will also cover insiders that purposefully or inadvertently breach the security of data and systems.  In addition, this chapter will explore a couple of common technologies that are used to detect network intrusions.  While we will not cover all the security systems available to professionals, readers will gain a firm understanding of the capabilities and goals this class of tooling offers.

**Objectives**
1. Explain how the vulnerability ecosystem works from discovery to remediation.
2. Understand the role of security training to prevent initial access by threat actors.
3. Demonstrate the use of threat detection systems commonly used in organizations.

## Industry Statistics
The impact to an organization that experiences a data breach can be highly destructive.  Depending on the threat actor and their level of success in the compromise, the organization could lose its ability to conduct business, lose its intellectual property and data, and damage its reputation, among many other risks.  Mature organizations will ensure to focus on security in order to prevent or minimize the realization of these risks.

In the Information Security chapter, we explored the attacker lifecycle, which usually begins with reconnaissance and leads to some sort of initial access.  If an organization is able to prevent the success of these early attack phases, they can avoid the impacts of an attacker's downstream phases as the attacker will be stopped before achieving later attack lifecycle phases.  Therefore, having a firm understanding of how attackers gain initial access is important in the effort to disrupt the attacker's objectives.  

There are a handful of large organizations that have a vantage point on the security of the internet.  For example, Verizon is a large internet service provider as it provides millions of devices internet access through their cellular networks.  This company takes security very seriously and has invested in the creation of security research that analyzes the types of breaches and malicious traffic patterns across their services.  From these experiences and data, they draw insights and statistics and publish their findings within an annual breach report.  But Verizon is not the only such company to provide this kind of research and reporting.  Many large cybersecurity companies, such as those that conduct incident investigations, leverage their cases and data to create similar reports that compare attacker methodologies that are used over time.  CrowdStrike is a highly reputable and offers high quality products and services that detect and respond to security threats in real time.

Studying these reports provides the industry with valuable insights on where an organization could focus their security efforts and investments.  The 2023 Verizon Data Breach Investigations Report (DBIR) includes many insightful statistics of the modern threat landscape.  For instance, they found that 83% of data breaches involved external actors - which implies that 17% were caused by internal actors.  Such a high proportion of external actors makes sense; however, if all an organization's efforts focused only on external threats, they would miss a material vector of security risk.  Further in the report, Verizon produces statistics on the causes of data breaches that include 49% Credentials, 12% Phishing, and 5% Exploits. [^1]  

![[../images/07/verizon_2023_dbir.png|Verizon 2023 DBIR - Summary of Findings|450]]

The image above from the DBIR illustrates the summary findings from its 2023 report.  It can provide the basis of a roadmap for an organization on how to think about and approach the prevention of data breaches.  Using these statistics, an organization may determine that the need for good password hygiene, strong authentication systems, email protections, and vulnerability management solutions can reduce the probability of common data breaches.  There is a lot of data produced by companies like Verizon and CrowdStrike that will not always reflect where an organization should invest security resources.  Not all concerned organizations have the same threat profile, so it is important to consider the context of a business's operations and other data sources before fully investing in a security vector solution.
## Vulnerability Management
It is safe to assume that all software has vulnerabilities regardless of whether they have been discovered or not.  It is also important to consider that all computer or network hardware requires software to function.  Therefore, you can only conclude that every device is vulnerable.  The process and tooling of identifying known security issues is called **vulnerability management** and is performed by security professionals.  Vulnerabilities are comprised of *software bugs* and *misconfigurations*.  Software bugs are usually unintentional defects within the software's logic or behavior that exposes some security risk.  They vary depending on the type of software, such as a website versus firmware, and the vector in which they can be exploited.  Vulnerabilities also range in the level of impact they could cause against a system.  Some vulnerabilities can be minor, such as information disclosure of a system error.  Other vulnerabilities can be significant, such as a remote code execution that allows an attacker full access to a system.  Such vulnerabilities are often cured through a *patch* or reconfiguration of the software that needs to be applied by the system maintainer.  

>[!warning] Warning - Vulnerability Versus Patch Management
>A common mistake is to conflate the administration and remediation of vulnerability management and patch management systems and processes.  Typically, vulnerability management is performed by security administrators that work independently from those responsible to apply patches.  Patch management solutions, such as Microsoft's Windows Server Update Services (WSUS) and SolarWind's Patch Manager, empower system administrators to identify and apply patches to systems.  Whereas vulnerability management systems like Nessus, which we will explore later in this chapter, identify systems that have vulnerabilities caused by missing security patches.  While it is understandable how these systems can be confused given their similarities, it is crucial to understand the difference and who is responsible to avoid conflicts of interest. 

The security of software is also dependent on its configuration, as some settings may undermine the system's security.  For example, exposing the MySQL database service through port 3306 to the internet would allow anonymous connections from anywhere in the world.  This is considered an insecure configuration; there should not be any need for internet-wide access to the database.  Ideally, the system should be configured to only allow network connections from within a private LAN network.
### Vulnerability Ecosystem
There is a rich community, driven ecosystem surrounding vulnerabilities and how their information is propagated across the industry.  The process begins with the identification of a security vulnerability that is sometimes discovered by a security researcher working independently or as part of a research firm.  They identify security issues in software using a number of methods that include static and dynamic testing.  Static testing usually includes analyzing a program that is not running, including the review of source code.  Dynamic testing involves checking for security issues while the software is running.  We will explore these testing efforts in the web security chapters later in this book.  Regardless of who and how a vulnerability is discovered, the researcher often confirms the validity of the vulnerability by developing a *proof of concept (POC)* or *exploitation code*.  

>[!info] Info - Zero-day Vulnerabilities
>A *zero-day vulnerability* is a vulnerability in which the software maintainer has had zero days advance notice to correct the issue with a software patch and to notify its userbase.  They are often identified by publicly disclosure or observing exploitation in the wild.  The severity could be exceedingly high if the zero-day is on widely used software that is commonly exposed to the internet as there is a high chance that malicious actors would immediately start exploiting it.

This POC code can be run to exploit the vulnerability, demonstrating the security issue.  It can also be used to assist the software maintainer to test patches to the vulnerable software by verifying that the exploit no longer works.  Once the researcher finds a vulnerability, they have a few options on how to proceed:

1. **Responsible Disclosure** - This process leads the security researcher to work with the software maintainer directly on the vulnerability and its remediation.  The resolution and speed of its availability are at the mercy of the software maintainer.  Some maintainers are quick to resolve while others may work very slowly to release a patch - sometimes many months.  In this disclosure, the researcher and maintainer come to terms on when a patch becomes available and the researcher waits a several days, usually 30, before publishing any research on the internet.  This window provides administrators time to update their systems before the researcher publicly announces the details on the security issue.  Without this window of time, many systems would be needlessly exposed to a known security issue that has instructions on how to exploit it on the internet.
2. **Public Disclosure** - A vulnerability and/or POC published on the internet for anyone to use without any advance notice to the software or system maintainer.  Such disclosure is not recommended as it leaves software users exposed to attack without having a solution to mitigate the vulnerability.  However, public disclosures occur frequently whether by accident or intentionally.  This can occur inadvertently if a researcher publishes on a public forum thinking that it is private.  But many times, security researchers, perhaps feeling jaded by vendor responses or lack thereof, publish vulnerabilities when there is no patch available.  The motivations may be out of spite or could result from exhausting efforts to disclose responsibly.  Sometimes software vendors do not see fit to resolve the security issue in a timely manner leaving the security researcher with no alternative options.  System administrators may want to know of security issues regardless of if the software maintainer is unresponsive.  The downside of this is that administrators only choice could be to shut down the affected system software if no fix is available.
3. **Exploit Market** - Another option available to researchers is to sell the vulnerability and its exploit on the black market to parties interested in it as a cyber weapon.  These are usually limited to the highest severity security bugs and can be financially lucrative for the researcher.  Some sales can be up to a million dollars.  *Black market* sales are those in which the researcher illegally, or at least unethically, sells the exploit to a group that plans to use it with malicious intent.  Authorities would likely prosecute the researcher, if ever caught.  However, in *grey market sales*, the researcher works with semi-legitimate exploit brokers who negotiate the sale of the exploit to a somewhat legitimate 3rd party.  For example, the United States' National Security Agency (NSA) has been known to legitimately purchase exploits from such channels. [^2]  But this can still be a risky endeavor for the researcher as they do not necessarily know or control who is buying the exploit since they are working through a broker. 

> [!info] Info - Distrust With Responsible Disclosure
> There is some level of distrust between companies and security researchers with the disclosure process.  Many years ago, software maintainers in the United States would press legal charges against security researchers for violating terms of use that contain anti-hacking provisions.  This led to the security community disclosing vulnerabilities anonymously within online forums that curtailed the vulnerability management process.  Nowadays, most organizations have come around to the disclosure process and may even encourage it through bug bounty programs.

The disclosure process can be laborious for the researcher, maintainer, and those running vulnerable software such as system administrators or developers.  The process is continuous as existing software is updated with new features and new security vulnerabilities are discovered.  Once a vulnerability is identified and a security patch is made available, a system administrator must update their systems to mitigate the security risk.  However, with such a dynamic environment where software is constantly changing and new vulnerabilities are identified, it would be impossible for a system administrator to monitor and apply security patches manually.  Multiply this scenario across all the software and systems that administrator is responsible for, and the problem quickly scales out of control.  Worse yet, every system administrator in every organization must also grapple with this issue.

Therefore, streamlining the vulnerability disclosure process and centralizing its data benefits all parties involved while promoting further discovery in the security field.  Over the years, the vulnerability management ecosystem has evolved with strong support from the US federal government and private organizations like MITRE.   Consider the following graphic which illustrates the interaction of several systems that support the vulnerability ecosystem.

![[../images/07/vuln_ecosystem.png|Vulnerability Management Ecosystem|350]]

After a security bug is discovered, the researcher files a **common vulnerabilities and exposures (CVE)** report.  Some large software maintainers like Microsoft, have dedicated classification and reporting requirements and are treated as a *CVE numbering authority (CNA)*.  CNA's require a researcher to file directly with the software maintainer and the maintainer integrates reports with the larger CVE program.  Otherwise, the CNA MITRE can be used for any software maintainer not designated as a CNA.  The MITRE organization is the original creator of the CVE system.  You may recall covering their MITRE ATT&CK Framework in earlier chapters.  They have contributed greatly to the security community as a non-profit organization and have established themselves as a critical resource for valuable security information.  

Continuing with the vulnerability lifecycle, the researcher completes an online form at cveform.mitre.org by completing details on what the vulnerability is, the software and versions that are applicable, and other relevant information.  MITRE will acknowledge the receipt of the request and after confirming that another CVE has not already been filed, will issue the researcher a CVE ID.  The CVE ID syntax is comprised of the year it was created followed by a dash and a 4+ digit number incremented by order of issuance, such as `CVE-2022-40624`.  At this point, the CVE is registered but excludes any details in the public listing to prevent malicious actors from exploiting the vulnerability before a patch has been created.  The researcher then works with the software maintainer to develop and to release a fix.  Once a patch is released, the maintainer and researcher wait a period of usually 30 days to provide administrators ample time to update their systems before publishing details of the vulnerability.  Once the waiting period is over, the researcher notifies MITRE to release the details of the CVE.  Simultaneously, the researcher may also publish full writeups of the vulnerability on other mediums, such as GitHub or a blog post, and tie those resources to the CVE ID under the references section.

Once the vulnerability is fully published at MITRE, the National Institute for Standards and Technology (NIST) examines the vulnerability and scores its severity using the **common vulnerability scoring system (CVSS)** calculator.  CVSS offers a consistent standard to be applied to all vulnerabilities in an effort to categorize the severity of security risk.  Version 3.1 of the online calculator can be found at https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator and is free to use.  It measures several factors based on defined inputs to achieve an overall score 1 through 10, with the latter being the highest severity.  With the CVSS score determined, NIST publishes the vulnerability within the **National Vulnerability Database (NVD)**.  This free database categorizes all vulnerabilities into streamlined formats that can be leveraged by automation vulnerability management tools.  

Vulnerability management scanning tools, such as Nessus, download the NVD database and use its information to discover vulnerable software deployed on systems and networks.  These scanning tools have been developed to identify the software and its version running on a system and compare them to the NVD.  If it finds a vulnerability associated with a version of software installed on a scanned system, it will list it as a security finding.  Vulnerability management tools are often deployed by system administrators or security teams; however, security teams are usually responsible for the use of the tool as a method to measure security risks within an environment.  The security analyst interpreting the vulnerability results will validate and develop treatment plans for the findings before working with system administrators on executing those remedial plans which typically require a system update.

>[!story] Story - Unauthenticated Remote Code Execution CVE-2022-40624
>In 2022, an unauthenticated remote code execution vulnerability on the Pfsense firewall PfBlockerNG plugin was making its way through the social media security channels.  This one caught my attention as I use pfBlockerNG and was very familiar with it.  The vulnerability was discovered and responsibly disclosed by r00t from ihteam.net where they wrote a nice blog post (https://www.ihteam.net/advisory/pfblockerng-unauth-rce-vulnerability/) and proof of concept documentation on the vulnerability.  The software maintainer was responsive and quickly released a patch due to the high severity of the issue with a CVSS score of 9.8 out of 10.
>
>I decided to load up the vulnerable version of the software in my lab environment and explore the source code where the vulnerability was reported.  I could see that user input from an HTTP host header was only partially validated before being passed to an exec function.  This software bug leads to an unauthenticated user's ability to execute arbitrary commands on the system.  Compounding the issue, the plugin and service runs as root which would give an attacker full administrative control over the firewall.  Looking at the applied patch, I could see that the developer updated the code to escape the user input nested in the exec function call, thus mitigating this particular bug.
>
>Surveying the rest of the source code within the PHP file that had the original vulnerability, I found that in just another dozen lines of code or so, there was another exec function using the same input pattern as the original vulnerability.  Surprised, I crafted a payload that exploited the vulnerability and confirmed a second undisclosed RCE vulnerability that was not yet patched!  I reached out to the software maintainer, submitted a report to MITRE and was assigned CVE-2022-40624.  The software maintainer quickly issued another patch, and I published the CVE and GitHub post sometime later (https://github.com/dhammon/pfBlockerNg-CVE-2022-40624).  
>![[../images/07/cve_2022-40624.png|NIST CVE-2022-40624 Record|400]]
>I could imagine how the original researcher overlooked this second vulnerability due to having found the original high impact issue which would have been very exciting.  They might have forgone any further research in light of the critical bug discovered due to their excitement or time constraints.  Just goes to show you that the only way you discover vulnerabilities is by being curious and going out of your way to look for them.  Come to think of it, as soon as I discovered my RCE vulnerability, I stopped looking too!

>[!activity] Activity 7.1 - Nessus Vulnerability Scan
>Using the Windows, Ubuntu, and Kali virtual machines, I will demonstrate the Nessus vulnerability scanning solution.  It is available for free with limited use, and I will install it on the Kali VM.  It is important to remember that using a vulnerability scanner against unauthorized systems is unethical, which is why I will be placing the VMs in a segmented NAT network.  Once the scan is complete, a list of vulnerabilities will be identified and available for review.
>
>Before starting any VMs, I set each VM's network settings to the previously created "NatNetwork" under the Settings and Network menu.  Once configured, I start each VM whose IP will be in the assigned 10.0.2.0/24 subnet range.
>
>![[../images/07/vuln_activity_network_setting.png|Assigning NAT Network Settings|600]]
>
>With the VMs started in the NatNetwork, I navigate to the Tenable website (https://www.tenable.com/products/nessus/activation-code) and register for the Nessus Essentials free license.  Tenable requires the use of a business email to register so I provided my college email address.  Once submitted I receive an email from Nessus with an activation code I can use when installing the tool.
>
>![[../images/07/vuln_activity_nessus_register.png|Nessus Registration Pages|600]]
>
>
> From within the Kali VM, I navigate to the Nessus download page hosted on Tenable's website (https://www.tenable.com/downloads/nessus?loginAttempted=true).  I select the `Linux - Debian - amd64` platform that matches the Kali operating system and download the Nessus version 10.7.0 that is the most up-to-date version at the time of this writing.
> ![[../images/07/vuln_activity_download.png|Nessus Installer Download|450]]
> 
> After a few moments, a DEB installer file is downloaded to my Downloads folder within Kali.  I open a terminal, update the system, and then install the Nessus package using the `dpkg` command.
> ```bash
> sudo apt update -y
> sudo dpkg -i ~/Downloads/Nessus*
> ```
> 
> ![[../images/07/vuln_activity_install.png|Installing Nessus on Kali|600]]
> 
> Upon successful completion, the installer output advises how to start Nessus and where to access it.
> 
> ![[../images/07/vuln_activity_install_output.png|Nessus Installation Output Instructions|600]]
> 
> From within the terminal, I run the `systemctl` start command to launch the Nessus service which includes a local web console.  I also check to confirm that the service is active and running using the status command.  Interestingly, the service runs as a daemon and the scanner is installed in the opt directory.
> ```bash
> sudo /bin/systemctl start nessusd.service
> systemctl status nessusd
> ```
> 
> ![[../images/07/vuln_activity_start_service.png|Starting Nessus Daemon|600]]
> 
> After the service is started, I launch Firefox within the Kali VM and navigate to https://kali:8834.  The browser presents me with an invalid certificate warning due to a self-signed certificate being used.  This is acceptable since this is only for demonstration purposes, so I press the `Advanced...` button and then `Accept the Risk and Continue` which leads me to the Nessus web console setup page.
> 
> ![[../images/07/vuln_activity_setup_screen.png|Local Nessus Setup Page|400]]
> 
> On the Setup page welcoming me to Nessus, I press the Continue button to proceed with the setup.  The next page offers a "Register for Nessus Essentials" option which I select, and press Continue.  This leads me to the "Get an activation code" step where I select the "Skip" button because I have already registered.  I am then led to a page with at field to enter the activation code sent to my email earlier in the activity.
> 
> ![[../images/07/vuln_activity_activation.png|Enter Nessus Activation Code Page|300]]
> 
> After entering my activation code and pressing Continue, and then Continue again to confirm the code, I am taken to the "Create a user account" page.  I enter my username `daniel` and a password and hit Submit.  Nessus will create an application administrator using these credentials which I will use to log into the system.
> 
> ![[../images/07/vuln_activity_user_create.png|Create User Account Page|300]]
> 
> Hitting Submit starts the initialization process where Nessus completes the installation and setup process.  
> 
> ![[../images/07/vuln_activity_initialization.png|Nessus Setup Initialization|300]]
> 
> The initialization of plugin downloads and installation takes a couple of minutes before the system logs in and I am presented with the Nessus home page.  A few temporary messages pop up that inform me the plugin data downloads are in progress and need to be completed before running a scan.  In the upper right corner of the page, I observe a spinning circular arrow icon suggesting that these efforts are in progress.  From previous experience, it will take an hour or two for the process to complete.
> 
> ![[../images/07/vuln_activity_splash_page.png|Nessus Logged In Splash Page]]
> 
> Once the installation of plugins and databases is complete, I am ready to start scanning.  I press the `New Scan` button on the main page upper right corner and select "Basic Network Scan" within the Scan Templates.
> 
> ![[../images/07/vuln_activity_scan_template.png|New Scan Template Selection|500]]
> 
> This leads me to the scan configuration page starting with the Settings tab, Basic menu section, and General subitem.  I enter the name of the scan as "Initial" and enter the CIDR range 10.0.2.0/24 for the targets.  Then I press the Save button at the bottom of the form.
> 
> ![[../images/07/vuln_activities_scan_setup.png|Scan Setup|550]]
> 
> The scan configuration is complete and is ready to be launched.  Since the Windows and Ubuntu VMs are within this NAT network subnet 10.0.2.0/24, they will be identified and scanned by Nessus.  Pressing the `Play` icon on the My Scans page entry launches the scan, which takes about half an hour to complete.
> 
> ![[../images/07/vuln_activity_scanning.png|Vulnerability Scan Launched]]
> 
> Eventually, the scan finishes and displays results per host by severity and volume.
> 
> ![[../images/07/vuln_activity_host_results.png|Vulnerabilities by Severity and Host]]
> 
> Selecting one of the hosts will list its vulnerabilities that were identified by the scan.  Selecting one of the vulnerabilities will reveal additional information on the issue including remediation guidelines.
> 
> ![[../images/07/vuln_activity_finding.png|High Severity Result For 10.0.2.15]]

## Email Architecture
As we learned from Verizon's DBIR, phishing emails and human interactions are material factors in relation to system and data breaches at organizations.  It is therefore worth understanding how email works, the risks it imposes, and how to secure it to best mitigate the threats faced by organizations.  Let us first begin with the basics of email system architecture.

![[../images/07/email_arch.png|Basic Email Architecture|400]]

Starting with the PC hardware on the bottom left corner, an email is created from the device's email software and then sent to its mail server using the *simple mail transfer protocol (SMTP)* over port 25 or the TLS encrypted port 587.  Mail servers are configured to maintain segregated mailboxes for each of its users' ensuring privacy between accounts.  Over SMTP, an email is relayed to the destination mail server by the receiving mail server.  The first mail server knows where to send the email due to the DNS *mail exchange (MX)* record associated with the domain of the receiver.  Many email system administrators will install an email security gateway device, sometimes on the same device as a *mail transfer agent (MTA)*, to inspect and relay incoming and outgoing email.  The email destined for the client on the bottom right of the diagram sits at their mail server until the client's device checks the mail server's inbox and retrieves any new messages.  Messages can be transferred from the server to the client via the *internet message access protocol (IMAP)* or the *post office protocol (POP)*.  IMAP protocol retrieves messages, over ports 143 or TLS encrypted port 993, but leaves a copy on the server.  This ensures that any other client device connected to the same mailbox can also retrieve messages.  Messages retrieved via POP, over ports 110 or TLS encrypted port 995, remove the email from the mail server storing the only copy on the client PC.
### Email System Risks
Understanding this basic email architecture, we can begin to see multiple places where attacks can occur.  Attackers positioned between mail clients and mail servers, or between mail servers, could intercept emails in clear text.  Attackers could also gain access to email accounts which will allow them to inspect all client messages or send emails directly from the victim's mailbox.  This has huge implications as many businesses conduct transactions over email inherently trusting the sender.  In addition, many systems have placed great reliance for their authentication recovery processes on the email system that registered with the service, which is clearly demonstrated using account reset procedures like "forgot my password".  Because those recovery systems rely on the integrity of the mailbox, if the mailbox is compromised, an attacker can easily pivot onto other systems by resetting the victim's password. 

Because email is used so heavily by individuals and organizations as a means of communication, it can be abused.  Email users often trust the content within an email or can be tricked by its contents, as is the case in email *phishing attacks*.  Here, a threat actor sends an email to a victim in an attempt to get the victim to click on a link, download a file, or perform some activity like changing an account number in a database.  Attached files in phishing attempts often include malware that could allow an attacker remote access to the victim's device.  Or in the case of a malicious link, the victim could be led to a spoofed website designed to harvest their credentials.  Malicious websites, or *phishing sites*, are designed to steal a victim's email credentials which can facilitate *business email compromise (BEC)*.  An example of this is when an attacker creates a fake Microsoft 365 login page that prompts victims for their username, password, and even a multifactor authentication token.  

Phishing emails are typically engineered to trick users by sending emails from domains that are very similar to a trusted domain.  For example, an attacker might register "go0gle.net" and a victim might mistake it for a legitimate Google domain.  Emails can also be *spoofed* in which the attacker sends the phishing email from a trusted domain address and user.  Sometimes the spoofing attempt will only be a veneer or vanity disguise, while other times it can be literally shown from the trusted domain depending on how insecure the mail server and DNS settings are.  Attackers may also use other victims with trusted email domains who have also had their mailboxes compromised from which to launch phishing attacks.  These efforts are made by the attacker to gain trust with the target victim and to create a more effective phishing campaign.
### Email Security
Phishing remains one of the most prolific and easiest ways attackers are able to obtain initial access to networks and systems.  However, there are many security features that can be used to protect email systems and users from falling victim to email threats.  The quintessential use of encryption in transit is an obvious solution to keep emails private as they traverse networks.  As suggested in the email architecture section of this chapter, SMTP, IMAP, and POP all support TLS encryption to prevent snooping between systems.  While these protocols ensure privacy while in transit, they do not ensure that the content of emails are kept private while being processed on servers and clients.  In fact, any email administrator will be able to open, read, and modify any email while it sits on the mail server.  An additional layer of encryption can be applied to the email content itself to maintain the confidentiality and integrity of the email.  One of the most popular content encryption options is the longstanding **Pretty Good Privacy (PGP)** encryption system which uses asymmetric public key cryptography between the sender and the receiver. 

>[!tip] Tip - End-to-End Encryption
>When a system ensures that the content of communications is encrypted where no intermediary system can access its plaintext data, the system is referred to as *end-to-end encryption*.

There are a few security solutions to prevent the spoofing of emails that use DNS and configurations on the mail server.  For example, the popular DNS TXT record can hold a **sender policy framework (SPF)** value which lists the domains and IP addresses that are allowed to send email as the respective domain.  Since DNS administrators control these records, they can be trusted.  Using an SPF record allows a mail server to identify if an email is being spoofed which allows it to reject emails reaching recipients.  For example, if I attempted to send you an email spoofing the Google.com domain, your mail server would receive my email and look up the Google domain's TXT SPF record to see the allowed domains and IP addresses that can send email from Google.  Because my email is not coming from an IP address listed on the SPF record, your mail server would likely flag it as suspicious and block it from reaching your inbox.  Another email security solution is the **domain keys identified mail (DKIM)** system which uses digital signatures to verify that emails are sourced from validated domains.  You may recall learning about digital signatures in the Cryptology chapter.  Here, a DNS record holds the DKIM public key, while the mail server maintains the private key used to validate message signatures.  The **domain based message authentication reporting and conformance (DMARC)** system enables administrators to set policies for handling failed SPF and DKIM messages.  Handling options include sending the email to quarantine, to reject, or to refer the domain and IP of the sender to a domain abuse registry.

Email gateways are another solution to provide email security.  These solutions act like an email firewall that can inspect email content and can identify threatening hallmarks such as malicious links or attachments, unknown or first-time senders, or other characteristics that could suggest the email might be malicious.  These systems determine whether to block or to allow an email based on a threat score against a threshold score set by email administrators.  If the threat score exceeds the threshold, an email may be quarantined or blocked.  Gateways can also scan attachments for malware effectively acting like an antivirus solution for mailboxes.  Another popular feature of these security devices is the insertion of security banners at the top of the email which notifies or cautions the email recipient of potential security abnormalities.  If a user does identify a potential phishing email, they can report it to the gateway offering security professionals the opportunity to manually inspect the email in further detail.  These systems also offer outbound email protection which can identify sensitive information leaving an organization, such as *personally identifiable information (PII)* or credit card data.
## Security Training

>[!activity] Activity 7.2 - Security Awareness Training
>Take a moment and consider why an enterprise would want or need to do end user security awareness training.  Recall any training that you may have had to do in school or at work.  What topics were covered and why do you think they are important?

People tend to be the weakest link when it comes to information security.  Humans are fallible and susceptible to making mistakes or to being tricked into doing something that they do not fully realize the consequences of at the time of the action.  Everyone gets busy and distracted at times and can inadvertently make an error that allows a threat to succeed with an attack.  However, many users can also be unaware of their responsibilities with protecting systems.  They might have a misunderstanding about how a system works or even a false sense of security.  I have often heard people, even managers, believe that they would never be the target of an attack.  This mentality is very dangerous, and attackers often rely on it to succeed in their attacks.  It is therefore crucial that all organization members undergo regular training that compels them to honestly consider the risks they face.  Too often such training is underappreciated or glossed over, but it remains a vital control that reminds individuals to stay aware of security risks.

The last section covered email security because phishing is such a prevalent attack method.  Any prevention in this area is a worthy effort, including training that focuses on phishing threats.  A popular learning system is through **simulated phishing** solutions, such as the very popular KnowBe4 platform.  This solution allows security teams to systematically send phishing emails  to their userbase and test their ability to identify the attack.  If a user clicks on a link in the email or opens one of its attachments, they fail the test and will usually undergo additional training.  All activity in these systems is aggregated and tracked so security management can measure how susceptible their userbase is to phishing attacks over time.

Training can be delivered to end users in a variety of formats using a few systems.  *Learning management systems (LMS)* are content development and delivery solutions that enable trainers to streamline the creation of learning modules and assign them to groups of users.  Such systems provide metrics on the level of completion and send reminder emails to assigned users in an effort to ensure timely completion.  LMSs also have the ability to support rich content like interactive widgets and quizzes to substantiate knowledge gained.  Many vendors have created **security awareness training** on LMS platforms designed for any organization.  Often this type of training is required annually because of regulatory requirements or standards demanded by key stakeholders.

Security training topics and content should ideally meet the user base where they are and pertain to their role within the organization.  It should cover their responsibilities, the practices they are expected to follow, and why it is important.  This can be challenging at scale as many users are sophisticated, having a firm grip on security, while other users cannot do enough training.  For instance, the IT help desk user should have an elevated understanding of security but should still be expected to complete security awareness training.  Ideally their training would be tailored to their role, perhaps focusing on matters like authenticating user requests before resetting passwords, which is a risky activity.  Even if a topic is already familiar to the user, it is still worth covering again for the sake of keeping security top of mind for the user.  The following list shows many topics that should be strongly considered to include in basic security awareness training:

- **Social Engineering** - Users can be tricked into providing information or access to systems by attackers.  Social engineering uses psychology to gain a victim's trust and get them to reveal information they might otherwise not.  Training should cover what social engineering is, provide examples of attacks, cover the mediums it can occur (phone, email, in-person), and detail how to remain diligent in preventing attack success, such as authenticating a person before providing them information or performing an action.
- **Passwords** - Basic password management and hygiene including what makes a good password (length, entropy) and how to store them using a *password manager*.  The topic should also cover good password practices like avoiding password reuse to prevent spraying attacks. 
- **Data Protection** - Describes what data is important to protect, how to handle that data, and when to grant a person access to it.  Training could include how to classify data and relay the importance of keeping it secure, such as not taking the data home or storing it on unauthorized systems.
- **Incident Response** - It is important that organization members understand what security threats to look for and how to report them.  If a user has a frictionless method of reporting, they are much more likely to provide security personnel with information that could detect or prevent data breaches.
- **Physical Security** - Often overlooked due to the assumption that an attacker would only attempt attacks remotely, physical security measures can be critical to information security.  Training should include topics like tailgating where an attacker follows someone into a building to avoid using a key card to unlock doors, locking computer stations when not in use to prevent someone from accessing logged in systems, and to watch out for rogue devices that look out of place, as they could be a *drop box* planted by an attacker.

## IDS/IPS
Attacker behaviors can be identified by the types of network packets they send, system processes they run, and system artifacts they create.  These clues are referred to as **indicators of attack (IoA)** and **indicators of compromise (IoC)** and can be programmed into monitoring or alerting systems that notify security analysts to investigate.  IoAs are caused by suspected attacker behavior prior to a breach of security or signal activity related to a breach.  An example of an IoA would be an incoming HTTP request that includes a malicious payload.  An IoC is a pattern that a breach of security has already occurred, such as the identification of malware installed on a computer endpoint.  Both IoAs and IoCs are written into detection rules for security systems by security engineers.  These engineers study malicious behaviors of attackers and malware to identify unique characteristics that can be specifically measured.  Common categories that can be used to identify malicious activity include filename syntax, IP addresses, domains, strings in files or packets, hexadecimal bytes in specific positions of requests or files, and many more.  When a security system triggers one or more of these identifiers written into rules, the system creates an alert for a security analyst to triage.

> [!note] Note - Other Monitoring Systems
> Malicious activity can also be detected in the system and application logs which are aggregated and monitored in a *system information and event management (SIEM)* solution.  You will have the opportunity to explore the SIEM solution Splunk in later chapters.

**Intrusion detection systems (IDS)** and **intrusion prevention systems (IPS)** are a class of security solutions that are designed to monitor for IoA and IoCs.  These solutions are commonly found within firewalls, endpoints or workstations, and standalone network devices.  They consist of a rules engine that can be fed custom rules or subscribed to proprietary or community-based rulesets.  As new attacks and breaches are discovered, researchers and engineers update rulesets to ensure that systems can detect the latest threats.  IDS systems are designed to run in *monitor only* mode and will trigger alerts when a threat is detected; IPS systems detect, block, and alert the potential malicious activity.  

These systems deployed on devices are referred to as *host-based IDS (HIDS)* and can monitor network, file, and process activities.  IDS/IPS systems are often found within secured networks installed on firewalls and routers or as stand-alone *security appliances*.  Network based IDS/IPS solution architecture options are *tap* or *inline*.  Under the tap architecture, the appliance is installed and connected to a networking device such as a router or switch.  The network device interfaces are *mirrored*, or traffic is cloned, and forwarded to the IDS appliance.  The appliance then inspects the traffic for IoA/IoCs and alerts appropriately.  This tap architecture only works for IDS since the inspected traffic is only a copy and the original, as demonstrated in the following image.

![[../images/07/tap_arch.png|IDS Tap Architecture|350]]

However, an inline architecture supports both IDS and IPS as all traffic is first routed through the security appliance before being passed along to the networking equipment.  The appliance can then drop network packets with IoA/IoCs preventing the malicious activity from reaching its destination.

![[../images/07/inline_arch.png|IDS/IPS Inline Architecture|350]]

The inline architecture could become a bottleneck for network activity as it must process and inspect all network traffic.  This could result in the unavailability of network resources which may be intolerable.  Under such requirements, using the tap architecture ensures that the network will not become unavailable due to the security appliance.  However, the tap architecture would not prevent malicious activity and often will not inspect all traffic if it reaches capacity.  Systems, network, and security engineers must come to terms for which risks they want to optimize, security or performance.

### Detection Rules
The quality of a written rule may depend on how well the IoA/IoC detects a given threat.  They should include descriptions, references to additional resources, be logically named, and labeled with an appropriate severity rating.  Another measurement of a well-written rule is by the number of *false positives (type 1)* and *false negatives (type 2)* errors they generate.  A rule that produces alerts on normal user or network activity will slow analyst productivity and create *alert fatigue* in which a real threat might be overlooked because the analyst has been conditioned to believe the rule is low quality.  Worse yet are false negatives in which the alerting system fails to notify the analyst of an actual threat.  Usually decreasing type 1 errors will increase type 2 errors or inversely decreasing type 2 will increase type 1.  Therefore, a careful balance needs to be achieved given resource constraints and the risk tolerance of the organization.  Some security systems allow for the creation of exceptions which allows analysts to *tune* a rule by muting it under specific conditions.  For example, an exception can be created that ignores the alerting activity from a specific IP address, which is often needed when running a vulnerability management scanner since it might appear as an IoA.

The syntax and layout of a rule is largely dependent on the security system for which it is being written.  One popular IDS/IPS security solution is the free and open-source tool Snort.  It has been around for many years and has wide community support.  The following image breaks down the anatomy of a demo rule from Snort's documentation on https://docs.snort.org/rules/.  

![[../images/07/snort_rule.png|Demo Snort Rule Anatomy|550]]

Each rule must include a header and option section.  The header is the first line of the rule and includes the action, TCP and/or UDP protocol, source address and port, directionality of the network request (ingress or egress), and the destination addresses or ports.  The system allows for macro variables and supports IP and port ranges.  The body of the rule is called options and is a list of key value pairs.  Many options are not required and only a few are listed in this image sample.  However, common options include the `msg` key which is used as the name or description of the alert, the `flow` of data, the `file_data`, the `content` to be found, the `service` to inspect, and the `sid` to uniquely index the rule.

>[!activity] Activity 7.3 - Snort PCAP Analysis
>Snort is a fantastic tool that supports preinstalled and custom rules.  I will use a packet capture from malware-traffic-analysis.net that maintains a growing list of network attack samples to practice analyzing.  Beware that the cases on malware-traffic-analysis.net contain real malware and you should proceed with caution.
>
>Using the Ubuntu VM in Bridge Adapter network mode, I log in, open a terminal, and install Snort after updating the machine.  I accept the default network configurations for Snort when the Package configuration interface pops up.
>```bash
>sudo apt update -y
>sudo apt install snort -y
>```
>
>![[../images/07/snort_activity_install.png|Installing Snort on Ubuntu VM|600]]
>
>Next, I download the PCAP from the accompanying support files and unzip its contents.  The file is originally from https://malware-traffic-analysis.net/ and has been password protected with the word `infected`.
>```bash
>cd ~/Downloads
>unzip 2016-04-16-traffic-analysis-exercise.pcap.zip
>```
>![[../images/07/snort_activity_unzip.png|Unzipping PCAP|600]]
>This PCAP includes case information surrounding a phishing site with a spoofed PayPal credentials form.  The indicators of attack include the IP address 91.194.91.203 on port 80 and the page includes the keyword "paypal".  With this information I create a Snort detection rule that can be used to detect network traffic reaching the malicious site.  The following command adds the custom rule to the local rules file in the Snort configuration.
>```bash
>sudo su -
>echo 'alert tcp 91.194.91.203 80 -> $HOME_NET any (msg:"Paypal phishing form"; content:"paypal"; sid:21637; rev:1;)' >> /etc/snort/rules/local.rules
>exit
>```
>
>![[../images/07/snort_activity_custom_rule.png|Creating Custom Snort Rule|600]]
>
>With the rule in place, I scan the PCAP file using Snort.  The following command uses the default configuration file, reads the PCAP file to the console, and has the options `-q` which removes the banner, `-K` enables logging mode, and `-A` that enables alert mode.
>```bash
>sudo snort -c /etc/snort/snort.conf -r 2016-04-16-traffic-analysis-exercise.pcap -q -k none -A console
>```
>
>![[../images/07/snort_activity_scan.png|Scanning PCAP With Snort|600]]
>
>Snort alerts on several items, but notably it alerts on the PayPal phishing from the rule created earlier!

## Data Loss Prevention
The Verizon DBIR suggests that a sizable percentage of data breaches are caused by insiders through both mistakes and malicious acts.  Organization members may seek to take company data out of authorized systems for a variety of purposes.  Sometimes they may not realize that they are forbidden from using a system or they may not even realize the repercussions of their actions.  I have seen organization members paste sensitive information into random third party online tools, such as a JSON beautifier, without considering that they just handed over data to an unauthorized third party!  Sometimes these insiders purposefully try to take data with them for personal gain.  I have conducted investigations in which an employee who was about to put in their two-week notice, but before doing so, made copies of customer contacts and sent them to their personal email address.  There is even more damage an insider could cause, especially for larger or restricted organizations, such as exfiltrating intellectual property to a competitor or a nation-state.

Regardless of the motivation, insiders pose a significant threat to the confidentiality of information at organizations.  There are several systems usually in use at most organizations that can assist with **data loss prevention (DLP)** in which a system identifies, alerts, and blocks data exfiltration attempts.  Traditionally, DLP efforts relied on existing tools such as disabling USB ports and removing DVD burners on workstations.  Other legacy efforts could rely on *URL filtering* at the firewall blocking certain file sharing websites, such as Dropbox, from being reachable from within organization networks.  Email systems also have capabilities built-in to identify and prohibit certain types of outbound emails by searching for strings of characters or *regular expressions* within the body of emails or file attachments.  These traditional methods are effective at blocking many types of inadvertent attempts, but they are neither centralized nor comprehensive.

The next generation of DLP solutions hitting the marketplace over the last several years solve for some of the challenges with the features of legacy tools.  Most of them require an organization to have a firm understanding of the type of data it wishes to protect, such as a clear data classification and labeling policy.  The DLP solution installs on workstations and proxies all network connections monitoring the destination and data contents while classifying the data in accordance with policies.  They build profiles of user behavior and rate each user by risk so that security analysts can prioritize efforts on those posing the most risk.  For instance, these systems could identify if an organization member has access to a lot of classified data and is visiting common job listing websites while having a resume file on their desktop.  The system would rate this behavior as a high risk and an analyst could monitor their actions more carefully. 

> [!warning] Warning - DLP and Privacy
> Given how intrusive DLP solutions have become, great concern has arisen for the privacy of organization members.  Within the US, many of these concerns are curtailed by setting a "no right to privacy policy."  However, in other countries, such employee privacy might be legally required.
## Deceptive Security
Defenders can leverage an attacker's own activity against them through **deceptive security** in which the malicious actor is tricked into setting off an alarm.  This can be accomplished by enticing them with a lure, like an asset that is too good to pass up.  After initial access, attackers may enumerate files and network devices from the compromised machine.  A carefully placed file or system with an interesting name may attract the attacker into opening the file or establishing a network connection.  Those within the network would otherwise have no business opening these files or establishing such network connections providing the defender with the opportunity to easily identify potentially malicious activity.

These deception techniques are designed to alert security analysts of potentially malicious activity that has already breached a network or system.  One deception technique is the use of **canary tokens**, named after the "canary in the coalmine" that would notify miners of poisonous gasses because the canary bird would be killed by the gas before the miners would.  Canary tokens are often stored within files, credentials or even database values.  If the file is opened, it reaches out to a server with the token value that is associated with metadata related to the placement of the file, as illustrated in the image below.

![[../images/07/canary.png|Attacker Triggering Alert From A Canary File|300]]

These work as rich file formats, like Microsoft Word, allow for rendering images from URLs.  Within canary images, the token value can be used in the source of the URL where the image is to be requested from, thus triggering the alert.  Similarly, a canary token can be placed within the contents of a database or file and a firewall rule can be created that alerts if the value is ever sent through the firewall.  This scenario would indicate that an attacker is attempting to exfiltrate sensitive data.

> [!tip] Tip - Thinkst Canary Tokens
> One of the industry leaders of deceptive security is Thinkst.  They maintain the free website https://canarytokens.org/generate where you can create a canary laced file and listener hosted on their servers.  Place the file on a file share and if anyone opens it, a connection with the canary value is made to the Thinkst servers.  Their servers then send an email alert notifying you that someone opened the file!

Another deception technique that attracts a malicious actor inside a network is a **honeypot**.  These are usually servers that have one or many network ports and services open to the network.  If any connection is made to the server, an alert is sent to security analysts to investigate.  A good honeypot is carefully designed so as to not alert the attacker that it is a honeypot, both before and after any connection attempts are made.  Many security researchers set up honeypots on the open internet in order to gather public attack statistics.  In fact, VulnCheck suggests that of the 200,000+ Atlassian Confluence servers on the internet at the time of this writing, 97% are suspected of being honeypots! [^3] 

![[../images/07/honeypots.png|Honeypot Network Setup|400]]

The image above illustrates an attacker making a network connection to a honeypot which in turn notifies the security team.  Network defenders set up honeypots within trusted networks to be notified should their perimeter be breached.  Both honeypots and canaries are excellent indicator of compromise (IoC) solutions that are widely used in mature security organizations.

> [!activity] Activity 7.4 - MySQL Honeypot
> I will demonstrate the installation and setup of a honeypot on the Ubuntu VM from Qeeqobx's honeypots Python module at https://github.com/qeeqbox/honeypots.  This honeypot will serve a MySQL database that appears like a functional service, but will produce logs of any activity.  A MySQL database would likely be of interest to an attacker since it could be full of valuable data.  These logs can be sent to a SIEM or other monitoring solutions to notify defenders.  Using the Kali VM, I will attempt a connection and observe the logging capabilities of the service.
> 
> After starting the Ubuntu VM in Bridge Adapter network mode and then logging in, I open a terminal install Python's Pip3 package manager, which will allow me to install python modules.
> ```bash
> sudo apt install python3-pip -y
> ```
> ![[../images/07/honey_activity_pip_install.png|Installing Python3 PIP|600]]
> Once Pip is installed, I install the honeypots Python module with the following command.  Several supporting dependencies are installed alongside the honeypots module.
> ```bash
> sudo apt install python3-pip -y
> pip3 install honeypots
> ```
> 
> ![[../images/07/honey_activity_install.png|Installing Honeypots Module|600]]
> 
> I also check the IP address of the Ubuntu VM to use later in the attack.  I can see my IP address is 192.168.4.169.
> ```bash
> ip a
> ```
> 
> ![[../images/07/honey_activity_ip.png|Ubuntu IP Address Check|600]]
> 
> The final step to set up the MySQL honeypot is to run Python specifying the honeypots module with the setup option that targets the MySQL service and port, as shown in the following command.  The command's output displays the service settings and suggests that everything looks good.
> ```bash
> python3 -m honeypots --setup mysql:3306
> ```
> ![[../images/07/honey_activity_honeypot_setup.png|Running the MySQL Honeypot|600]]
> With the honeypot setup and running, I start the Kali VM in Bridge Adapter network mode which will serve as the attacker.  After logging in and opening a terminal, I attempt a MySQL connection to the honeypot using the MySQL client already installed on Kali.  I guess a username (admin) and password (Password123) to simulate an attacker probe but receive a valid MySQL error 1045.  This would lead the attacker to believe that the MySQL server is valid, but the guessed credentials were not valid.
> ```bash
> mysql -h 192.168.4.169 -u admin -pPassword123
> ```
> 
> ![[../images/07/honey_activity_attack.png|Attacker Connecting to MySQL Honeypot|600]]
> 
> Jumping over to the Ubuntu VM and observing the honeypot log, I can see the attacker connection attempt!  It includes information such as the timestamp, guessed username, and source IP address from where the attack came.
> 
> ![[../images/07/honey_activity_log.png|Honeypot Log of Attack|600]]
> 
> In a full setup, this log would be used to trigger an alert to a security operations team that would investigate and determine the severity of the event.

## Exercises
> [!exercise] Exercise 7.1 - Breach Report
> In this task, you will read the CrowdStrike 2023 Global Threat Report and briefly summarize its contents. 
> #### Step 1 - Read and Report
> Download the CrowdStrike 2023 Global Threat Report and read it while taking notes on any interesting facts you discover.  Write a brief ½ page summary describing where and why a company may want to invest its security resources.  The report should be written in with Executive Management and/or Board of Directors as the target audience.  Avoid too much use of technical jargon. 


> [!exercise] Exercise 7.2 - Nessus Vulnerability Scan
> Using all three of your VMs in a NAT Network for this task, you will perform Nessus vulnerability scans on the Windows and Ubuntu VMs from the Kali VM. 
> 
> #### Step 1 - Configure Network
> Within VirtualBox, select Tools, the Settings menu, and the Network Option.  Select the “NAT Networks” tab under the Properties button.  Press the “Create” button to generate a new NAT Network that you will use for all of your VMs.  You will notice that a new network named “NatNetwork” for subnet 10.0.2.0/24 was created.  Note this IP range as you will need it when configuring Nessus in later steps.  
> 
> With all VMs powered off, navigate to each VMs' Settings, select Network, and choose “NAT Network” attachment and the Name “NatNetwork”.  Start each VM after they have been configured on the NatNetwork. 
> #### Step 2 - Obtain Activation Code
> The Nessus Essentials product allows students a free activation code that can be used on up to 16 IP addresses.  From your host machine, navigate to https://www.tenable.com/products/nessus/activation-code and select “Register Now” under the “Nessus Essentials” option.   
> 
> Enter your name and your email.  Note that most free email providers may be blocked from acquiring a free activation code.  Check your email for the activation code.  You will need this after Nessus is installed in the following steps. 
> #### Step 3 - Download and Install Nessus
> From your Kali VM, navigate to https://www.tenable.com/downloads/nessus?loginAttempted=true.  Select “Linux - Debian – amd64" in the Platform dropdown menu and then press the Download button and accept the license agreement.  With the Nessus DEB file downloaded to your Downloads folder, open a terminal, change directories to your Downloads folder, and install the package.  You may need to run `sudo apt update -y` prior to installing the package. 
> ```bash
> sudo apt update -y 
> cd ~/Downloads 
> sudo dpkg -i Nessus* 
> ```
> Start the Nessus daemon. 
> ```bash
> sudo /bin/systemctl start nessusd.service 
> ```
> Open your browser within the Kali VM and go to “https://kali:8834” to access the Nessus console locally.  Select Advanced and Accept the Risk and Continue, if prompted.  
> #### Step 4 - Configure Nessus
> Now that Nessus is installed and running in the Kali VM with the console loaded in the browser, press the Continue button.  Select Register for Nessus Essentials and then Continue.  Press the Skip section since you already have an activation code.  Enter your activation code that you should have received in your email inbox during a previous step and press Continue.  Press Continue again when presented with your License Information.  
> 
> Enter a username and password for Nessus and then Submit.  Nessus will download the plugins and data, which may take some time to complete.  After a minute of plugin installation, you will be redirected to the console home page.  Plugin and feed data will continue to download in the background, which may take 1-2 hours to complete. 
> 
> You must wait for the feeds to download before the “New Scan” button becomes available.  The feeds take about an hour to download.  You will know when the feed downloads are complete because the New Scan button will no longer be greyed out. 
> #### Step 5 - Create and Launch Scan
> With Nessus running and logged in on the Kali VM, press the New Scan button on the main page.  Select the “Basic Network Scan” under the vulnerabilities section.  Under the Settings tab, Basic menu section, select General.  Name the scan “Initial-YOURNAME" and enter the Targets as 10.0.2.0/24.  Then press the Save button at the bottom of the form.  
> 
> Observe that the scan configuration is now listed under the My Scans page.  Click the name of the scan to open more options and then press Launch in the upper right corner.  Observe that the scan now shows the status as running!  Allow 20 minutes for the scan to complete before progressing to the next step. 
> #### Step 6 - Analyze Results
> Now that the scan has been completed, explore the Hosts and Vulnerabilities tabs.  The vulnerabilities are listed in order of severity.  Only a few items of concern were identified.  Explore further details on one of the items by clicking on the vulnerability.  Within a paragraph, describe the vulnerability, how to fix it, and why it is a concern.


> [!exercise] Exercise 7.3 - Snort Detection
> In this task you will use Snort to analyze a packet capture from malware-traffic-analysis.net. 
> #### Step 1 - Install Snort
> On your Ubuntu VM with Bridge Adapter network mode, login and open a terminal.  Apply updates on your system using the following command. 
> ```bash
> sudo apt update -y
> ```
> Install Snort using `apt`.  Accept default Snort network configuration. 
> ```bash
> sudo apt install snort -y
> ```
> Confirm Snort installed by running its help command. 
> ```bash
> snort --help
> ```
> #### Step 2 - Download Malicious PCAP
> > [!warning] WARNING! Malware ahead
> > You will download a PCAP from malware-traffic-analysis.net.  Some of these PCAP files will have real malicious traffic capture from real malware including their downloads and stagers.  Handle with care as this PCAP could include malicious binaries that if extracted and run, could compromise your system. 
> 
> Within the Ubuntu VM, download the accompanying file "2016-04-16-traffic-analysis-exercise.pcap.zip” which is a zipped PCAP.  In your Ubuntu terminal, change directory to the Downloads folder. 
> ```bash
> cd ~/Downloads
> ```
> Unzip the zipped PCAP file. The password is “infected”. 
> ```bash
> unzip 2016-04-16-traffic-analysis-exercise.pcap  
> ```
> #### Step 3 - Create Custom Rule
> You will create a custom rule to detect if a known malicious webserver has been accessed and credential form submitted.  Switch user to root, then echo the rule into the `local.rules` file, then exit the root terminal. 
> ```bash
> sudo su -
> echo 'alert tcp 91.194.91.203 80 -> $HOME_NET any (msg:"Paypal phishing form"; content:"paypal"; sid:21637; rev:1;)' >> /etc/snort/rules/local.rules  
> ```
> #### Step 4 - Analyze the PCAP
> Run Snort against the unzipped PCAP file in your Downloads folder. Observe that the PayPal rule was triggered! 
> ```bash
> sudo snort -c /etc/snort/snort.conf -r 2016-04-16-traffic-analysis-exercise.pcap -q -K none -A console 
> ```


>[!exercise] Exercise 7.4 - MySQL Honeypot
>You will use the opensource Python honeypots module to create a honeypot running on your Ubuntu VM in Bridge Adapter network mode.  You will then attack the Ubuntu VM from your Kali VM also in Bridge Adapter network mode. https://github.com/qeeqbox/honeypots 
>#### Step 1 - Install Honeypots
>From your Ubuntu VM, install python3-pip. 
>```bash
>sudo apt install python3-pip
>```
>After pip3 has installed, install the honeypots module. 
>```bash
>pip3 install honeypots 
>```
>Check your IP address. Note this value as you will need it when attacking from the Kali VM. 
>```bash
>ip a
>```
>#### Step 2 - Setup MySQL Honeypot
>In this step you will setup a MySQL honeypot running on port 3306. 
>```bash
>python3 -m honeypots --setup mysql:3306 
>```
>Observe that everything is running correctly and the terminal is standing by for connections. If any connections are made, they will be logged in the standard output. 
>#### Step 3 - Attack the MySQL Port
>From your Kali VM, launch a terminal and make a connection to your Ubutntu VM using the mysql client. Make sure to replace the <UBUNTU_IP> with the IP address of the Ubuntu VM. 
>```bash
>mysql -h <UBUNTU_IP> -u test -ptest 
>```
>Return to the Ubuntu VM and observe attack registered! 

[^1]:2023 Verizon Data Breach Investigations Report; 2023 Verizon
[^2]: NSA bought Hacking tools from 'Vupen', a French based zero-day Exploit Seller; September 18 2013; Mohit Kumar, The Hacker News; https://thehackernews.com/2013/09/nsa-bought-hacking-tools-from-vupen.html
[^3]: There Are Too Many Damn Honeypots; February 2, 2024; Jacob Baines; https://vulncheck.com/blog/too-many-honeypots