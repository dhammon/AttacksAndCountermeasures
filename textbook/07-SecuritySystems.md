# Security Systems
![](../images/07/security_patch.jpg)

There are preventative and detective controls that security professionals can implement to protect the security of computer systems and networks.  Tooling often accompanies a control, where some technology or software is used to achieve the control.  The aim of some of these systems are to prevent the initial compromise of systems.  This chapter starts with an overview of statistics from leading cybersecurity groups that analyze industry trends on how organizations are compromised.  Because some of the leading ways include vulnerable software and susceptible end users, we cover tooling and processes that aim to prevent attackers getting into systems.  Another concern relates to insiders purposefully or inadvertently breaching the security of data and systems so we will explore the systems that protect organizations from insider threat.  But attackers may still achieve access to systems so cyber defense professionals need add identify threats when they happen to provide immediate response.  This chapter will explore a couple common technologies used that detect network intrusions.

**Objectives**
1. Explain how the vulnerability ecosystem works from vulnerability discovery to repair.
2. Understand the role of security training to prevent initial access threats.
3. Demonstrate the use of threat detection systems commonly used in organizations.

## Industry Statistics
The impact to an organization that experiences a data breach can be highly destructive.  Depending on the threat actor and their level of success in the compromise, the organization could lose its ability to conduct business, lose its intellectual property and data, and damage its reputation among many other risks.  Mature organizations will ensure a focus of security to prevent or minimize the realization of these risks.

In the Information Security chapter we explored the attacker lifecycle which usually begins with reconnaissance and leads to some sort of initial access.  If an organization is able to prevent the success of these early attack phases they can avoid the impacts of an attacker's downstream phases as the attacker won't get to those phases.  Therefore, having a firm understanding on how attackers gain initial access is important in the effort to disrupt their attack lifecycle early in the process.  

There are a handful of large organizations that have a vantage point on the security of the internet.  For example, Verizon is a very large internet service provider as it provides millions of devices internet access through their cellular networks.  This company takes security very seriously and has invested in the creation of security research that analyzes the types of breaches and malicious traffic across their provided services.  From these experiences and data they draw insights and statistics by industry and other cohorts within a breach report each year.  But Verizon isn't the only such company to provide this kind of research and reporting.  Many large cybersecurity companies, such as those that conduct incident investigations, leverage their cases and data to create similar reports that compare the attacker methodologies used over time.  One such company is CrowdStrike who is highly reputable offering high quality products and services that detect and respond to security threats in real time.

Leveraging such reports provide the industry with valuable insights on where an organization could focus their security efforts and investments.  The 2023 Verizon Data Breach Investigations Report (DBIR) includes many insightful statistics of the modern threat landscape.  For instance, they found that 83% of data breaches were from external actors - which implies that 17% were caused by internal actors.  Such a high proportion of external actors makes sense; however, if all an organization's efforts focused only on external threats they would miss a material vector of security risk.  Further in the report Verizon produces statistics on the causes of data breaches that includes 49% Credentials, 12% Phishing, and %5 Exploits. [^1]  

![[../images/07/verizon_2023_dbir.png|Verizon 2023 DBIR - Summary of Findings|450]]

The image above from the DBIR illustrates the described summary findings.  It can provide the basis of a roadmap on how to think about data breaches and their prevention  Determining the need for good password hygiene, strong authentication systems, email protections, and vulnerability management solutions can reduce the probability of a data breach.  There is a lot of data produced by companies like Verizon and CrowdStrike and not all concerned organizations have the same threat profile, so it is important to consider the context of a businesses operations and other data sources before fully investing into a security vector solution.
## Vulnerability Management
It is safe to assume that all software has vulnerabilities, discovered or undiscovered, and all hardware requires software at some level.  Therefore, you can only conclude that everything is vulnerable.  The process and tooling of identifying such security issues is known as **vulnerability management** and is executed by security professionals.  Vulnerabilities comprise of *software bugs* and *misconfigurations*.  Software bug are usually unintentionally defects within the software's logic or behavior that expose some security risk.  They vary greatly depending on the type of software, such as a website versus firmware, and the vector in which they can be exploited, and the impact they may cause.  Such vulnerabilities are often cured through a *patch* of the software that needs to be applied by the system maintainer.  

>[!warning] Warning - Vulnerability Versus Patch Management
>A common mistake is to conflate the administration and remediation of vulnerability management and patch management systems and processes.  Typically, vulnerability management is performed by a security administrators that work independently from those responsible to apply patches.  Patch management solutions, such as Microsoft's Windows Server Update Services (WSUS) and SolarWind's Patch Manager empower system administrators to identify and apply patches to systems.  Whereas vulnerability management systems, like Nessus which we will explore later in this chapter, identify systems that have vulnerabilities often due to missing security patches.  While it is understandable how these systems can be conflated given their similarities, understanding the difference and who is responsible is crucial for avoiding conflicts of interests. 

The security of software is also dependent upon its secure configuration.  In this class of vulnerability software may have insecure settings that are applied exposing it to security risk.  For example, exposing the MySQL database service and port 3306 to the internet would allow anonymous connections from anywhere in the world.  This is considered an insecure configuration as there shouldn't be any need for internet-wide access to the database.  Instead the system should be configured to only allow network connections from within a private LAN network, at least ideally.

### Vulnerability Ecosystem
There is a rich community driven ecosystem surrounding vulnerabilities and how their information is propagated across the industry.  The process begins with the identification of a security vulnerability often by a security researcher working independently or as part of a research firm.  They identify security issues in software using a number of methods that include static and dynamic testing.  Static testing usually includes reviewing the source code or a program that is not running and search for vulnerabilities while dynamic testing involves checking for security issues while the software is running.  We will explore such testing efforts in the Web Security chapter later in this book.  Regardless who and how a vulnerability is discovered, the researcher often confirms the validity of the vulnerability by developing a *proof of concept (POC)* or *exploitation code*.  

>[!info] Info - Zero-day Vulnerabilities
>A *zero-day vulnerability* is a vulnerability that has been publicly disclosed or discovered being actively exploited in which the software maintainer has had zero days advanced notice to correct with a software patch.  The severity could be exceedingly high if the zero-day is on a widely used software that is commonly exposed to the internet as it has a high chance of immediately being used by malicious actors.

This POC code can be ran to exploit the vulnerability proving the security issue which can be used to test software installations.  Once the vulnerability is confirmed valid the researcher has a few options on how to proceed:

1. **Public Disclosure** - Publish the the vulnerability and/or POC onto the internet for anyone to use.  Such disclosure is not recommended as it leaves software users exposed to attack without having a solution to mitigate the vulnerability.  However, public disclosures occur frequently by accident or on purpose.  This can occur inadvertently if a researcher publishes on a public forum thinking that it is private.  But many times security researchers, maybe feeling jaded by vendor responses or lack thereof, publish vulnerabilities publicly when there is no patch.  The motivations may be out of spite or could be as a result of exhausting efforts to disclose responsibly.  Sometimes software vendors do not see fit to resolve the security issue in a timely manner leaving the security researcher with no alternative options.  System administrators may want to know of security issues regardless if the software maintainer is responsive.  The downside of this is that administrators only choice could be to shutdown the affected system software as no fix is available.
2. **Responsible Disclosure** - This process leads the security researcher to work with the software maintainer directly on the vulnerability and its remediation.  The resolution and speed of its availability are at the mercy of the software maintainer.  Some maintainers are quick to resolve while others may work very slowly to release a patch - sometimes many months.  In this disclosure the researcher and maintainer come to terms on when a patch becomes available and the research waits a number of days, usually 30, before publishing any research work onto the internet.  This window provides administrators time to update their systems before the researcher publicly announces the details on the security issue.  Without this window of time, many systems would be needlessly exposed to a known security issue that has instructions on how to exploit it on the internet.
3. **Market Sales** - Another option available to researchers includes the market sales of the vulnerability and exploit to parties interested in their use as a cyber weapon.  These are usually limited to the highest severity security bugs and can be financially lucrative for the researcher.  Some sales can be up to a million dollars.  *Black market* sales are where the researcher illegally, or at least unethically, sells the exploit to a group that plans to use it with malicious intent.  Authorities would likely prosecute the researcher, if ever caught.  However, in *grey market sales*, the researcher works with semi-legitimate exploit brokers who negotiate the sale of the exploit to a somewhat legitimate 3rd party.  For example, the United States' National Security Agency (NSA) has been known to legitimately purchase exploits from such channels.  But this can still be a risky endeavor for the researcher as they do not necessarily know or control who is buying the exploit as they are working through a broker.  If the broker were to sell the exploit to a nation-state agency outside of the researcher's country they could be prosecuted for selling ammunitions or arms to a foreign adversary or treason.

> [!info] Info - Distrust With Responsible Disclosure
> There is some level of distrust between companies and security researchers have with the disclosure process.  Many years ago software maintainers in the United States would press legal charges against security researchers for violating terms of use usually containing anti-hacking provisions.  This led to the security community disclosing vulnerabilities anonymously within online forums which curtailed the vulnerability management process.  Nowadays most organizations have come around to the disclosure process and may even encourage it through bug bounty programs.

The disclosure process is very manual requiring the communication between two parties and there have been a lot of vulnerabilities discovered over the years.  A security researcher making a blogpost about the vulnerability or the software maintainer discretely releasing a patch can be difficult for system administrators to monitor - especially if they have to manage thousands of software in an organization.  Streamlining the vulnerability disclosure process and centralizing the data would benefit all parties involved while promoting further innovation in the field.  Over the years the vulnerability management ecosystem has evolved with strong support from the federal government and private organizations.   Consider the following graphic which illustrates the interaction of several systems that support the ecosystem.

![[../images/07/vuln_ecosystem.png|Vulnerability Management Ecosystem|350]]

After a security bug is discovered the research files a **common vulnerabilities and exposures (CVE)** report.  Some software maintainers, like Microsoft, are so large and are classified as a *CVE numbering authority (CNA)* in which a researcher files directly with them and the maintainer integrates with the CVE program.  Otherwise, the CNA MITRE can be used for any software maintainer not authorized by the CVE program.  The MITRE organization are the original creators of the CVE system and you may recall covering the MITRE Att&ck Framework in earlier chapters.  They have contributed greatly to the security community as a non-profit organization and have established themselves as a critical resource of valuable information.  The researcher completes an online form at cveform.mitre.org completing details on what the vulnerability is, the software and versions that are applicable, and other relevant information.  MITRE will acknowledge the receipt of the request and after confirming that another CVE has not already been filed will issue the researcher a CVE ID.  The CVE ID syntax is comprised of the year it was created followed by a dash and a 4+ digit number in order of issuance such as `CVE-2022-40624`.  At this point the CVE is registered but excludes any details in the public listing as to prevent malicious actors from exploiting the vulnerability before a patch has been created.  The researcher then works with the software maintainer to develop and release a fix, provide administrators ample time to update their systems, and then may choose to publish the finding's details with MITRE.  They may also publish on other mediums, such as GitHub or a blog post, and tie those resources to the CVE ID under the references section.

Once the vulnerability is fully published at MITRE, the National Institute for Standards and Technology (NIST) examines the vulnerability and scores its severity using the **common vulnerability scoring system (CVSS)** calculator.  CVSS offers a consistent standard to be applied to all vulnerabilities in an effort to categorize the severity of security risk.  Version 3.1 of the online calculator can be found at https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator and is free to use.  It measures several factors based on defined inputs to achieve an overall score 1 through 10 with the latter being the highest severity.  With the CVSS score determined NIST publishes the vulnerability within the **National Vulnerability Database (NVD)**.  This free database categorizes all vulnerabilities into streamlined formats that can be leveraged by automation vulnerability management tools.  Vulnerability management scanning tools, such as Nessus, download the database and use its information to discover vulnerable software deployed on systems being targeted by the scan.  These scanning tools have been developed to identify the software and its version running on a system and compare that to the NVD.  If it finds a vulnerability associated with a version of software installed on a targeted system it will list it as a security finding.  Vulnerability management tools are often deployed by system administrators or security teams; however, security teams are often responsible for the use of the tool as a method to understand security risk within an environment.  The security analyst interpreting the vulnerability results will validate and develop treatment plans for the findings before working with system administrators on executing those remedial plans.

>[!story] Story - Unauthenticated Remote Code Execution CVE-2022-40624
>In 2022 an unauthenticated remote code execution vulnerability on firewall pfsense's pfBlockerNG plugin was making its way through the social media security channels.  This one caught my attention as I have used pfBlockerNG in the past and was familiar with it.  The vulnerability was discovered and responsibly disclosed by r00t from ihteam.net where they wrote up a nice blog post (https://www.ihteam.net/advisory/pfblockerng-unauth-rce-vulnerability/) and proof of concept documentation on the vulnerability.  The software maintainer was responsive and quickly released a patch given the high severity of the issue, CVSS score of 9.8 out of 10.
>
>I decided to load up the vulnerable version of the software in my lab environment and explore the source code where the vulnerability was reported.  I could see that user input from an HTTP host header was only partially validated before being passed to an unencoded exec function.  This software bug leads to an unauthenticated user's ability to execute arbitrary commands on the system.  Worst yet, the plugin and service runs as root which would give an attacker full administrative control over the firewall.  Looking at the applied patch I could see that the developer updated the code to encode the input nested in the exec function call, thus mitigating this particular bug.
>
>Surveying the source code of the vulnerable PHP file further, in just another dozen lines of code or so, I saw another exec function using the same input pattern as the original vulnerability.  Surprised, I crafted a payload that would exploit the vulnerability and I confirmed a second RCE vulnerability that was not yet patched.  I reached out to the software maintainer, submitted a report to MITRE and was assigned CVE-2022-40624.  The software maintainer quickly issued another patch and I published the CVE and GitHub post sometime later (https://github.com/dhammon/pfBlockerNg-CVE-2022-40624).  
>![[../images/07/cve_2022-40624.png|NIST CVE-2022-40624 Record|400]]
>I could imagine how the original researcher could have overlooked this second vulnerability having found the original issue with such a high impact would have been very exciting.  They might have forgone any further research in light of the critical bug discovered.  Just goes to show you that the only way you discover vulnerabilities is that you have to be curious and look for them.  Come to think of it, as soon as I discovered my RCE vulnerability I stopped looking too!

>[!activity] Activity 7.1 - Nessus Vulnerability Scan
>Using the Windows, Ubuntu, and Kali virtual machines I will demonstrate the Nessus vulnerability scanning solution.  It is available for free with limited use and I will install it on the Kali VM. It is important to remember that using a vulnerability scanner against unauthorized systems is unethical, which is why I will be placing the VMs in a segmented NAT network.  Once the scan completes a list of vulnerabilities found will be available for review.
>
>Before starting any VMs I set each VM's network settings to the previously created "NatNetwork" under the Settings and Network menu.  Once configured I start each VM whose IP will be in the assigned 10.0.2.0/24 subnet range.
>![[../images/07/vuln_activity_network_setting.png|Assigning NAT Network Settings|600]]
>With the VMs started in the NatNetwork, I navigate to the Tenable website (https://www.tenable.com/products/nessus/activation-code) and register for the Nessus Essentials free license.  Tenable requires the use of a business email to register so I provided my college email address.  Once submitted I receive and email from Nessus with an activation code I can use when installing the tool.
>![[../images/07/vuln_activity_nessus_register.png|Nessus Registration Pages|600]]
> From within the Kali VM, I navigate to the Nessus download page hosted on Tenable's website (https://www.tenable.com/downloads/nessus?loginAttempted=true).  I select the `Linux - Debian - amd64` platform that matches the Kali operating system and download the Nessus version 10.7.0 which is the most up-to-date version at the time of this writing.
> ![[../images/07/vuln_activity_download.png|Nessus Installer Download|450]]
> After a few moments the DEB installer file download completes which can be found in the Downloads folder of my user's account.  I open a terminal and update the system then install the Nessus package using dpkg.
> ```bash
> sudo apt update -y
> sudo dpkg -i ~/Downloads/Nessus*
> ```
> ![[../images/07/vuln_activity_install.png|Installing Nessus on Kali|600]]
> Upon successful installation the installer output advises how to start Nessus and where to access it.
> ![[../images/07/vuln_activity_install_output.png|Nessus Installation Output Instructions|600]]
> From within the terminal I run the systemctl start command to launch the Nessus service which includes a local web console.  I also check to confirm the service is active and running using the status command.  Interestingly the service runs as a daemon and the scanner is installed in the opt directory.
> ```bash
> sudo /bin/systemctl start nessusd.service
> systemctl status nessusd
> ```
> ![[../images/07/vuln_activity_start_service.png|Starting Nessus Daemon|600]]
> After the service is started I launch Firefox within the Kali VM and navigate to https://kali:8834.  The browser presents me with an invalid certificate warning due to a self-signed certificate being used.  This is acceptable since this is only for demonstration purposes so I press the Advanced... button and then Accept the Risk and Continue which leads me to the Nessus web console setup page.
> ![[../images/07/vuln_activity_setup_screen.png|Local Nessus Setup Page|400]]
> On the Setup page, welcoming me to Nessus, I press the Continue button to proceed with the setup.  The next page offers a "Register for Nessus Essentials" option which I select and press Continue.  This leads me to the "Get an activation code" step but because I have already registered a chose the Skip button where I am lead to a page to enter the activation code sent to my email earlier in the activity.
> ![[../images/07/vuln_activity_activation.png|Enter Nessus Activation Code Page|300]]
> After entering my activation code and pressing Continue, and then Continue again to confirm the code, I am taken to the "Create a user account" page.  I enter my username `daniel` and a password and hit Submit.  Nessus will create an application administrator using these credentials which I'll use to log into the system.
> ![[../images/07/vuln_activity_user_create.png|Create User Account Page|300]]
> Hitting Submit starts the initialization process where Nessus completes the installation and setup process.  
> ![[../images/07/vuln_activity_initialization.png|Nessus Setup Initialization|300]]
> The initialization of plugin downloads and installation takes a couple minutes before the system logs in and I'm presented with the Nessus splash page.  A few toast messages are presented that advise plugin downloads and data downloads are in progress and need to be completed before running a scan.  I can see in the upper right corner of the page a spinning circular arrow icon suggesting these efforts are in progress.  From previous experience it takes an hour or two for the process to complete.
> ![[../images/07/vuln_activity_splash_page.png|Nessus Logged In Splash Page]]
> Once the installation of plugins and databases are complete I am ready to start scanning.  I press the New Scan button on the main page upper right corner and select "Basic Network Scan" within the Scan Templates.
> ![[../images/07/vuln_activity_scan_template.png|New Scan Template Selection|500]]
> This leads me to the scan configuration pages starting with the Settings tab, Basic menu section, and General subitem.  I enter the name of the scan as "Initial" and enter the CIDR range 10.0.2.0/24 for the targets.  Then I press the Save button at the bottom of the form.
> ![[../images/07/vuln_activities_scan_setup.png|Scan Setup|550]]
> The scan configuration is complete and is ready to be launched.  Since the Windows and Ubuntu VMs are within this NAT network subnet 10.0.2.0/24 they will be identified and scanned by Nessus.  Pressing the Play icon on the My Scans page for the created scan launches the scan which takes about half an hour to complete.
> ![[../images/07/vuln_activity_scanning.png|Vulnerability Scan Launched]]
> Eventually the scan finishes and displays results per host by severity and volume.
> ![[../images/07/vuln_activity_host_results.png|Vulnerabilities by Severity and Host]]
> Selecting a host lists the vulnerabilities that are affected and then selecting a vulnerability reveals more information on it including remediation guidelines.
> ![[../images/07/vuln_activity_finding.png|High Severity Result For 10.0.2.15]]

## Email Architecture
As we learned from Verizon's DBIR phishing emails and human interactions are material factors in relation to data breaches at organizations.  It is therefore worth understanding how email works, the risks it imposes, and how to secure it to best mitigate the threats faced by organizations.  Let's first begin with the basics of email system architecture.

![[../images/07/email_arch.png|Basic Email Architecture|400]]
Starting with the client on the bottom left corner, and email is created on the devices email client and is sent to the mail server over *simple mail transport protocol (SMTP)* over port 25 or the TLS encrypted port 587.  Mail servers are configured to maintain segregated mailboxes for each of its users ensuring privacy between accounts.  When the mail server receives the client email it then forwards to the mail server of the recipient also over SMTP.  The first mail server knows where to send the email due to the DNS *mail exchange (MX)* record.  Many email system administrators will use an email security gateway device, or *master transfer agent (MTA)*, to inspect and relay incoming and outgoing email.  The email destined to the client on the bottom right of the diagram sits at their mail server until the client's device checks the mail server's inbox and retrieves any new messages.  Messages can be transferred from the server to the client via the *internet message access protocol (IMAP)* or the *post office protocol (POP)*.  IMAP retrieved messages, over ports 143 or TLS encrypted port 993, but leaves a copy on the server.  This ensures any other client device connected to the same mailbox can also retrieve messages.  Messages retrieve via POP, over ports 110 or TLS encrypted port 995, remove the email from the mail server storing the only copy on the client.
### Email System Risks
Understanding this basic architecture we can begin to see multiple places where attacks can occur.  Attackers positioned between mail clients and mail servers, or between mail servers, could intercept emails in clear text.  Attackers could also gain access to email accounts which will allow them to inspect all client messages or send emails directly from the mailbox.  This has huge implications as many businesses conduct transactions over email trusting the sender.  In addition many systems have placed great reliance on their authentication recovery processes on the email that registered with the service, such as with "forgot my password" processes that send an account recovery email to the account holder.  An attacker in control of such a mailbox can reset passwords to many other systems and move laterally between systems.

Because email is used so heavily by individuals and organizations as a means of communication it can be abused.  Email users often trust the content within an email or can be tricked by its contents as is the case in email phishing attacks.  Here, a threat actor sends an email to a victim in an attempt to get the user to click on a link or download a file.  Attached files to emails in phishing attempts often include malware that could allow an attacker remote access to the victim's device.  Or, in the case of a malicious link, the victim could be lead to a spoofed website designed to harvest their credentials, such as a Microsoft 365 login page that is in control of the attacker.  Phishing emails are typically engineered to trick users by sending emails from domain's that are very similar to a trusted domain.  For example, an attacker might register "go0gle.net" and a victim might mistake it for a legitimate Google domain.  Emails can also be *spoofed* in which the attacker sends the phishing email with a trusted from address.  Sometimes the spoofing attempt will only be a veneer or vanity disguise while other times it can be literally show from the trusted domain depending on how insecure the mail server and DNS settings are.
### Email Security
Phishing remains one of the most prolific and easiest ways attackers are able to obtain initial access to networks and systems.  However there are many security features that can be used to protect email systems and users from falling victim to email threats.  The quintessential use of encryption in transit is an obvious solution to keep emails private as they traverse networks.  As suggested in the email architecture section of this chapter, SMTP, IMAP, and POP all support TLS encryption to prevent snooping.  While these protocols ensure privacy while in transit, they do not ensure that content of emails is kept private while being processed on services and clients.  In fact, any email administrator will be able to open, read, and modify any email while it sits on the mail server.  An additional layer of encryption can be applied to the email content itself to maintain the confidentiality and integrity of the email.  One of the most popular content encryption options is the longstanding **pretty good privacy (PGP)** encryption system which uses asymmetric public key cryptography between the sender and the receiver. 

There are a few security solutions to prevent spoofing of emails that are configured on the mail server and other systems such as DNS.  For example, the popular DNS TXT record can hold a **sender policy framework (SPF)** value which lists the domains and IP addresses that are allowed to send email under the respective domain.  Because DNS administrators are in control of these records, they can be trusted as and using an SPF record allows a mail server to reject emails from reaching recipients.  For example, if I attempted to send you an email spoofing the Google.com domain, your mail server would receive my email and lookup the Google domain's TXT SPF record and see the allowed domains and IP addresses that can send email from Google.  Because my email isn't coming from an IP address listed on the SPF record, your mail server would block or deny it from ever reaching your inbox.  Another email security solution is the **domain keys identified mail (DKIM)** system which uses digital signature to verify emails are sourced from validated domains.  You may recall learning about digital signatures in the Cryptology chapter.  Here, DIKIM holds the public key while the mail server holds the private key used to validate message signatures.  The **domain based message authentication reporting and conformance (DMARC)** system instructs mail servers on how to handle SPF and DKIM messages.  The handling of such emails is usually sending the email to quarantine, failing, or even sending the spoofed domain abuse reports.

Email gateways are another solution to provide email security.  These solutions act like an email next generation firewall that can inspect email content and identify threatening hallmarks such as malicious links or attachments, unknown or first time senders, among other characteristics the suggest the email could be malicious.  These system determine whether to block or allow an email based on a threat score against a threshold score set my email administrators.  If the threat score exceeds the threshold an email may be quarantined or blocked.  Gateways can also scan attachments for malware effectively acting like an antivirus solution for mailboxes.  Another popular feature of these security devices are the insertion of security banners at the top of the email which notify or caution the email recipient of potential security abnormalities helping users be on the guard malfeasance - that is if they actually heed the warnings!  If a user does identify a potential phishing email, they can report the email to the gateway offering security professionals the opportunity to manually inspect the email in further detail.  These systems also offer outbound email protection which can identify sensitive information leaving the company, such as *personally identifiable information (PII)* or credit card data.
## Security Training

>[!activity] Activity 7.2 - Security Awareness Training
>Take a moment and consider why an enterprise would want or need to do end user security awareness training.  Recall any trainings that you may have had to do in school or at work.  What topics were covered and why do you think they are important?

People tend to be the weakest link when it comes to information security.  Humans are infallible and susceptible to make mistakes or be tricked into doing something they don't fully realize the consequences of at the time of the action.  Everyone gets busy and distracted at times and can inadvertently make an error that allows a threat to succeed with an attack.  However, many users can also be unaware of their responsibility with protecting systems.  They might have a misunderstanding on how a system works or a false sense of security.  I've often heard people, even managers, believe that they would never be the target of an attack.  This mentality is very dangerous and attackers often rely on it, a lowered guard, or oblivious requirement to succeed in their attacks.  It is therefore crucial that all organization members undergo regular mandatory training that compels them to honestly consider the risks they face.  Too often such training is underappreciated or glossed over, but it remains a vital control to continued information security assurance.

The last section covered email security because phishing is such a prevalent attacking method.  Any prevention in this area is therefore a worthy effort, including phishing training schemes.  A popular learning system is the **simulated phishing** solutions, such as the very popular KnowBe4 platform.  This solution allows security teams to send phishing emails systematically to their userbase to test their wherewithal to attack.  If a user clicks on a link in the email or opens one of its attachments, they fail the test and will usually undergo additional training.  All activity in these systems are aggregated and tracked so security management can measure how susceptible their userbase is to phishing attacks overtime.

Training can be delivered to end users in a variety of formats using a few systems.  *Learning management systems (LMS)* are content development and delivery solutions that enable trainers to streamline the creation of learning modules and assign to groups of users.  Such systems provide metrics on the level of completion and sends reminder emails to assigned users to ensure timely completion.  LMS also have the ability to support rich content like interactive widgets and quizzes to substantiate knowledge gained.  Many vendors have created **security awareness training** on LMS platforms designed for all organizations to take.  Often this type of training is required annually because of regulation or standards demanded by key stakeholders.

Security training topics and content should ideally meet the userbase where they are and pertain to their activities.  It should cover their responsibilities, the practices they are expected to follow, and how it is important.  This can be challenging at scale as many users are sophisticated having a firm grip on security while other users can't do enough training.  For instance, the IT help desk user should have an elevated understanding of security but should still be expected to complete security awareness training.  Ideally their training would be tailored for their role, perhaps focusing on matters like authenticating user requests before resetting passwords - a risky activity indeed.  Even if a topic is already familiar to the user it is still worth covering again for sake of reminding the user keeping it top of mind.  The following list shows many topics that should be strongly considered to include in basic security awareness training:

- **Social Engineering** - Users can be tricked into providing information or access to systems by attackers.  Social engineering uses psychology to gain a victim's trust and getting them to reveal information they might otherwise not.  Training should cover what social engineer is, give examples of attacks, cover the mediums it can occur (phone, email, in-person), and detail how to remain diligent to prevent an attacks success such as authenticating a person.
- **Passwords** - Basic password management and hygiene including what makes a good password (length, entropy) and how to store passwords using a password manager.  The topic should also cover good password practices like avoiding password reuse to prevent spraying attacks. 
- **Data Protection** - Describes what data is important to protect, how to handle that data, and when to grant a person access to the sensitive information.  Training could include how to classify data and relay the importance of keeping it secure, such as not taking the data home or storing it on unauthorized systems.
- **Incident Response** - It is important that organization members understand what security threats to look out for and how to report them.  If a user has a frictionless method of reporting they are much more likely to provide security personnel with information that could detect or prevent data breaches.
- **Physical Security** - Often overlooked due to the assumption that an attacker would only attempt attacks remotely, physical security measure can be critical to information security.  Training should include topics like tailgating where an attacker follows someone into a building to avoid using a key card to unlock doors, locking computer stations when not in use to prevent someone from accessing logged in systems, and to watch out for rogue devices that look out of place as they could be a drop box planted by an attacker.

## IDS/IPS
Attacker behaviors can be inspected by the types of network packets they send, system processes they run, and system artifacts they create.  These clues are referred to as **indicators of attack (IoA)** and **indicators of compromise (IoC)** and can be programed into monitoring or alerting systems that notify security analysts to investigate.  IoAs are caused by suspected attacker behavior prior to a successful breach of security.  An example of an IoA would be an incoming HTTP request that includes a malicious payload.  An IoC is hallmark that a breach of security has already occurred such as the identification of malware installation on a computer endpoint.  Both IoAs and IoCs are written into detection rules for security systems by security engineers.  They achieve this by first studying malicious behaviors of attackers and malware and identify unique characteristics that can be specifically measured.  Common categories to identify include filename syntax, IP addresses, strings in files or packets, hexadecimal bytes in specific positions of requests, and many more.  When a security system triggers on one or more of these identifiers written into rules, the system creates an alert for a security analyst to triage.

> [!note] Note - Other Monitoring Systems
> Malicious activity can also be detected in the system and application logs which are aggregated and monitored for in a *system information and event management (SIEM)* solution.

**Intrusion detection systems (IDS)** and **intrusion preventions systems (IPS)** are a class of security system that is designed to monitor for IoA and IoCs.  These solutions are commonly found within firewalls, endpoints or workstations, and standalone network devices.  They include a rules engine that can be fed custom rules or subscribed to proprietary or community based rulesets.  As new attacks and breaches are discovered, researchers and engineers update rulesets to ensure systems can detect the latest threats.  IDS systems are designed to run in *monitor only* mode and will trigger alerts when a threat is detected; whereas IPS systems detect, block, and alert the potential malicious activity.  These systems deployed on devices are referred to as *host-based IDS (HIDS)* and can monitor network, file, and process activities.  IDS/IPS systems are often found within secured networks installed on firewalls and routers or as stand alone *security appliances*.  Network based IDS/IPS solution architecture options are *tap* or *inline*.  Under the tap architecture the appliance is installed and connected to a networking device such as a router or switch.  The network devices interfaces are *mirrored*, or traffic is cloned, and forwarded to the IDS appliance.  The appliance then inspects the traffic for IoA/IoCs and alerts as appropriate.  This tap architecture only works for IDS as the traffic that is inspected is only a copy and the original traffic is passed through as demonstrated in the following image.
![[../images/07/tap_arch.png|IDS Tap Architecture|350]]
However, an inline architecture supports both IDS and IPS as all traffic is first routed through the security appliance before being passed along to the networking equipment.  The appliance can then drop network packets with IoA/IoCs preventing the malicious activity from reaching its destination.
![[../images/07/inline_arch.png|IDS/IPS Inline Architecture|350]]
The inline architecture could become a bottleneck for network activity as it must process and inspect all network traffic.  This could result in the unavailability of network resources which may be intolerable in which case using the tap architecture ensures the network won't become unavailable due to the security appliance.  However, the tap architecture wouldn't prevent malicious activity and often won't inspect all traffic if it reaches capacity.  Systems, network, and security engineers must come to terms on which risks they want to optimize for, security or performance.
### Detection Rules
The quality of a written rule may depend on how clearly the IoA/IoC to determine the security significance.  They should include descriptions, references to additional resources, be logically named, and labeled with an appropriate severity rating.  Another measurement of a well written rule is the number of *false positives (type 1)* and *false negatives (type 2)* errors they generate.  A rule that produces alerts on normal user or network activity will slow analyst productivity and worse create *alert fatigue* in which a real threat might be overlooked because the analyst has been conditioned to believe the rule is low quality.  Worse yet are false negatives where the alerting system fails to notify the analyst of an actual threat.  Usually decreasing type 1 errors will increase type 2 errors or inversely decreasing type 2 will increase type 1.  Therefore, a careful balance needs to be achieve given resource constraints and the risk tolerance of the organization.  Some security systems allow for the creation of exceptions which allows analysts to *tune* a rule by muting it under specific conditions.  For example, an exception can be created that ignores the alerting activity from a specific IP address which is often needed when running a vulnerability management scanner.

The syntax and layout of a rule is largely dependent on the security system it is being written for.  One popular IDS/IPS security solution is the free and opensource tool Snort.  It has been around for many years and has wide community support.  The following image breaks down the anatomy of a demo rule from Snorts documentation on https://docs.snort.org/rules/.  
![[../images/07/snort_rule.png|Demo Snort Rule Anatomy|550]]
Each rule must include a header and option section.  The header is the first line of the rule and includes the action, TCP and/or UDP protocol, source address and port, directionality of the network request ingress or egress, and the destination addresses or ports.  They system allows for macro variable creations and supports IP and port ranges.  The body of the rule, options, is a list of key value pairs.  There are several options available that are not listed in this sample, therefore many options are not required.  However common options include the `msg` key which is used as the name or description of the alert, the flow of data, file data, the content to be found, the service to inspect, and an `sid` to uniquely index the rule.

>[!activity] Activity 7.3 - Snort PCAP Analysis
>Snort is a fantastic tool that supports preinstalled and custom rules.  I will use a packet capture from malware-traffic-analysis.net who maintains a growing list of network attack samples to practice analyzing.  Beware that the cases on malware-traffic-analysis.net contain real malware and you should proceed with caution.
>
>Using the Ubuntu VM in Bridge Adapter network mode, I login, open a terminal, and install Snort after updating the machine.  I accept the default network configurations for Snort when the Package configuration interface pops up.
>```bash
>sudo apt update -y
>sudo apt install snort -y
>```
>![[../images/07/snort_activity_install.png|Installing Snort on Ubuntu VM|600]]
>Next I download the PCAP from the accompanying support files and unzip its contents.  The file is originally from https://malware-traffic-analysis.net/ and has been password protected with the word `infected`.
>```bash
>cd ~/Downloads
>unzip 2016-04-16-traffic-analysis-exercise.pcap.zip
>```
>![[../images/07/snort_activity_unzip.png|Unzipping PCAP|600]]
>This PCAP includes case information surrounding a phishing site with a spoofed Paypal credentials form.  The indicators of attack include the IP address 91.194.91.203 on port 80 and the page includes the keyword "paypal".  With this information I create a Snort detection rule that can be used to detect network traffic reaching the malicious site.  The following command adds the custom rule to the local rules file in the Snort configuration.
>```bash
>sudo su -
>echo 'alert tcp 91.194.91.203 80 -> $HOME_NET any (msg:"Paypal phishing form"; content:"paypal"; sid:21637; rev:1;)' >> /etc/snort/rules/local.rules
>exit
>```
>![[../images/07/snort_activity_custom_rule.png|Creating Custom Snort Rule|600]]
>With the rule in place I scan the case PCAP file using Snort.  The following command uses the default configuration file, reads the PCAP file to the console, and has the options `-q` which removes the banner, `-K` enables logging mode, and `-A` that enables alert mode.
>```bash
>sudo snort -c /etc/snort/snort.conf -r 2016-04-16-traffic-analysis-exercise.pcap -q -K none -A console
>```
>![[../images/07/snort_activity_scan.png|Scanning PCAP With Snort|600]]
>Snort alerts on several items, but notably it alerts on the Paypal phishing form rule created earlier!

## Data Loss Prevention
The Verizon DBIR suggests a material percentage of data breaches are caused by insiders through both mistakes as well as malicious acts.  Organization members may seek to take company data out of authorized systems for a variety of purposes.  Sometimes they may not realize that they are forbidden of using a system or they may not even realize the repercussions of their actions.  I've seen organization members paste sensitive information into random third party online tools, such as a JSON beautifier, without considering they just handed over that data to an unauthorized third party!  Sometimes these insiders purposefully try to take data with them for personal gain.  I have conducted investigations where an employee who was about to put in their two week notice but before doing so made copies of customer contacts and sent them to their personal email address.  Still yet, especially for larger or restricted organizations, malicious insiders could plan to exfiltrate intellectual property to a competitor or a nation-state.

Regardless of the motivation, insiders pose a significant threat to the confidentiality of information at organizations.  There are several systems usually in use at most organizations that can assist with **data loss prevention (DLP)** in which the system can identify, alert, and block data exfiltration attempts.  Traditionally, DLP efforts relied on existing tools such as disabling USB ports removing DVD burners on workstations.  Other legacy efforts could rely on *URL filtering* at the firewall blocking certain file sharing websites, such as Dropbox, from being reachable from within organization networks.  Email systems also have capabilities built in to identify and prohibit certain types of outbound emails by searching for strings of characters or *regular expressions* within the body of emails or file attachments.  These traditional methods are effective at blocking many types of inadvertent attempts but they are not centralized or comprehensive.

The next generation of DLP solutions hitting the marketplace over the last several years solve for some of the challenges with legacy features of existing tools.  Most of them require an organization to have a firm understanding of the type of data it wishes to protect, such as a clear data classification and labeling scheme.  The DLP solution installs on workstations and proxies all network connections monitoring the destination and data contents while classifying the data in accordance with policies.  They build profiles of user behavior and rate each user by risk so that security analysts can focus efforts on those posing the most risk.  For instance, these systems could identify if an organization member has access to a lot of classified data and are visiting common job listing websites while having a resume file on their desktop.  The system would rate this behavior as a high risk and an analyst could monitor their actions more carefully.  The current DLP solutions enable administrators to limit a vast array of websites data is permitted to be transferred to as well - keeping up to date with the less popular or more obscure sites someone might use to extract data from the organization.
## Honeypots
Canary tokens

> [!activity] Activity 7.4 - MySQL Honeypot
> lol

## Exercises
> [!exercise] Exercise 7.1 - Breach Report
> In this task you will read the CrowdStrike 2023 Global Threat Report and briefly summarize its contents. 
> #### Step 1 - Read and Report
> Download the CrowdStrike 2023 Global Threat Report and read it while taking notes on any interesting facts you discovered.  Write a brief ½ page summary describing where a company may want to invest its security resources and why.  The report should be written in with Executive Management and/or Board of Directors as the target audience.  Avoid too much use of technical jargon. 

> [!exercise] Exercise 7.2 - Nessus Vulnerability Scan
> Using all three of your VMs in a NAT Network for this task, you will perform Nessus vulnerability scans on the Windows and Ubuntu VMs from the Kali VM. 
> 
> #### Step 1 - Configure Network
> Within VirtualBox, select Tools, the Settings menu, and the Network Option.  Select the “NAT Networks” tab under the Properties button.  Press the “Create” button to generate a new NAT Network that you will use for all of your VMs.  You will notice a new network named “NatNetwork” for subnet 10.0.2.0/24 was created.  Note this IP range as you’ll need it when configuring Nessus in later steps.  
> 
> With all VMs powered off, navigate to each VMs Settings, select Network, and choose “NAT Network” attachment and the Name “NatNetwork”.  Start each VM after they have been configured on the NatNetwork. 
> #### Step 2 - Obtain Activation Code
> The Nessus Essentials product allows students a free activation code that can be used on up to 16 IPs.  From your host machine, navigate to https://www.tenable.com/products/nessus/activation-code and select “Register Now” under the “Nessus Essentials” option.   
> 
> Enter your name and your email.  Note that most free email providers may be blocked from acquiring a free activation code.  Check your email for the activation code.  You will need this after Nessus is installed in the following steps. 
> #### Step 3 - Download and Install Nessus
> From your Kali VM, navigate to https://www.tenable.com/downloads/nessus?loginAttempted=true.  Select “Linux - Debian – amd64" in the Platform dropdown menu and then press the Download button and accept the license agreement.  With the Nessus DEB file downloaded to your Downloads folder, open a terminal and change directories to your Downloads folder and install the package.  You may need to run `sudo apt update -y` prior to installing the package. 
> ```bash
> sudo apt update -y 
> cd ~/Downloads 
> sudo dpkg -I Nessus* 
> ```
> Start the Nessus daemon. 
> ```bash
> sudo /bin/systemctl start nessusd.service 
> ```
> Open your browser within the Kali VM and go to “https://kali:8834” to access the Nessus console locally.  Select Advanced and Accept the Risk and Continue if prompted.  
> #### Step 4 - Configure Nessus
> Now that Nessus is installed and running in the Kali VM with the console loaded in the browser, press the Continue button. Select Register for Nessus Essentials and then Continue.  Press the Skip section since you already have an activation code.  Enter your activation code that you should have received in your email inbox during a previous step and press Continue.  Press Continue again when presented with your License Information.  
> 
> Enter a username and password for Nessus and then Submit.  Nessus will download the plugins and data which may take some time to complete.  After a minute of plugin installation you will be redirected to the console home page.  Plugin and feed data will continue to download in the background which may take 1-2 hours to complete. 
> 
> You must wait for the feeds to download before the “New Scan” button becomes available.  The feeds take about an hour to download.  You will know when the feed downloads complete because the New Scan button will no longer be greyed out. 
> #### Step 5 - Create and Launch Scan
> With Nessus running and logged in on the Kali VM, press the New Scan button on the main page.  Select the “Basic Network Scan” under the vulnerabilities section.  Under the Settings tab, Basic menu section, select General.  Name the scan “Initial” and enter the Targets as 10.0.2.0/24.  Then press the Save button at the bottom of the form.  
> 
> Observe the scan configuration is now listed under the My Scans page.  Click the name of the scan to open more options and then press Launch in the upper right corner.  Observe the scan show status running!  Allow 20 minutes for the scan to complete before progressing to the next step. 
> #### Step 6 - Analyze Results
> Now that the scan has completed, explore the Hosts and Vulnerabilities tabs.  The vulnerabilities are listed in order of severity.  Only a few items of concern were identified.  Explore further details on one of the items by clicking on the vulnerability. 

> [!exercise] Exercise 7.3 - Snort Detection
> In this task you will use Snort to analyze a packet capture from malware-traffic-analysis.net. 
> #### Step 1 - Install Snort
> On your Ubuntu VM with Bridge Adapter network mode, login and open a terminal.  Apply updates on your system using the following command. 
> ```bash
> sudo apt update -y
> ```
> Install Snort using apt.  Accept default Snort network configuration. 
> ```bash
> sudo apt install snort -y
> ```
> Confirm Snort installed by running its help command. 
> ```bash
> snort --help
> ```
> #### Step 2 - Download Malicious PCAP
> WARNING! You will download a PCAP from malware-traffic-analysis.net. Some of these PCAP files will have real malicious traffic capture from real malware including their downloads and stagers. Handle with care as this PCAP could include malicious binaries that if extracted and ran can compromise your system. 
> 
> Within the Ubuntu VM, open the browser and navigate to “https://www.malware-traffic-analysis.net/2016/04/16/2016-04-16-traffic-analysis-exercise.pcap.zip” which will download the zipped PCAP to your Downloads folder.  In your Ubuntu terminal, change directory to the Downloads folder. 
> ```bash
> cd ~/Downloads
> ```
> Unzip the zipped PCAP file. The password is “infected”. 
> ```bash
> unzip 2016-04-16-traffic-analysis-exercise.pcap  
> ```
> #### Step 3 - Create Custom Rule
> We will create a custom rule to detect if a known malicious webserver has been accessed and credential form submitted. Switch user to root, then echo the rule into the local.rules file, then exit the root terminal. 
> ```bash
> sudo su -
> echo 'alert tcp 91.194.91.203 80 -> $HOME_NET any (msg:"Paypal phishing form"; content:"paypal"; sid:21637; rev:1;)' >> /etc/snort/rules/local.rules  
> ```
> #### Step 4 - Analyze the PCAP
> Run Snort against the unzipped PCAP file in your Downloads folder. Observe the Paypal rule was triggered! 
> ```bash
> sudo snort -c /etc/snort/snort.conf -r 2016-04-16-traffic-analysis-exercise.pcap -q -K none -A console 
> ```

>[!exercise] Exercise 7.4 - MySQL Honeypot
>You will use the opensource python honeypots module to create a honeypot running on your Ubuntu VM in Bridge Adapter network mode. You will then attack the Ubuntu VM from your Kali VM also in Bridge Adapter network mode. https://github.com/qeeqbox/honeypots 
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