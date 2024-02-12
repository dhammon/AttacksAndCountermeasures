# Operating System Security
![](../images/05/windows_linux.jpg)

Modern operating systems (OS) have built in security measures to ensure that information stored and processed by them are secured to authorized users.  Administrators and object owners can determine who and what level of access accounts have on the device.  Operating systems also have features that have security implications that we will explore.  These features themselves can be abused to enable an attacker to meet their impact objectives.  Learning about them and how they work will help us when we explore persistence and privilege escalation techniques in the next chapter.

**Objectives**
1. Understanding of Linux file, user, service, and logging systems.
2. Conduct system hardening and benchmarking activities using Inspec.
3. Learn the file, user, service, and logging systems in Windows.
4. Perform Windows Defender antivirus bypass.
## Linux
In this section we will emphasize basic Linux file, authorization, user, and password systems.  It will also explore how the operating system manages running applications, scheduled tasks, and logs which hold significant security value.
### File System
Within Linux, *everything is a file*, or they are at least represented that way.  Unintuitive things like memory space and devices are files that can be navigated to and explored using directory commands or file explorer applications.  When the operating system is installed, a partition is created on the hard drive and a file system is created.  The file system includes the instructions of how files and folders are stored within the partition, including the metadata of files, name requirements, and space requirements.  The **extension version 4 (ext4)** is the current and most common file system in support at the time of this writing.

The ext4 file system provides nested folders or directories under a root folder represented by a forward slash `/`.  Within the root folder are several other folders that meet the needs of the operating system  Some of the most common folders are represented in the following figure.
![[../images/05/linux_folders.png|Linux Folder Structure]]
Starting on the left and working our way to the right, we have the */bin* directory.  This folder holds the binaries, or applications, installed on the system.  The `/dev` folder has all the hardware devices that the operating system detects as connected.  Configuration files for the OS and the applications installed on it are located within the `/etc` folder.  Users files are stored within folders named after their usernames in the `/home` directory. The `/lib` folder contains library files needed during system boot and the `/mnt` folder is often used to hold references to other drives mounted on the device.  The `/opt` folder is used to store optional files and apps and is where I often store applications that I've installed on the system.  The `/root` directory is the root user's home directory and is unavailable to other system users.  Similar to the bin directory, the `/sbin` directory also holds binaries but the sbin folder is used for system specific applications.  The `/tmp` folder stores files that are used that are disposable and will be automatically deleted after some time or when rebooted.  Shared read only files, binaries, libraries, and manuals are installed in the `/usr` directory and variable files such as data files, logs, mail inboxes, and application files are within the `/var` directory.

In a following section we will discuss users and groups, but for now you should understand that everything in Linux is a file, and every file is owned by an user, or *owner*, and group.  Usually the user that creates the file is the owner and has full discretion on how it is used.  The owner, or any account within a group, can make any changes to the file.  File ownership can be altered using the built-in utility `chown`.  For example, a file `example.txt` can have its ownership changed to the `daniel` user and the `dev` group with the following command: `chown daniel:dev example.txt`.
### Authorization System
Permission Sets
Read, Write, Execute
Change Mode
Special Permissions
### User System
Users
Groups
### Password System
/etc/passwd
/etc/shadow

> [!activity] Activity - Shadow Cracking

>[!exercise] Exercise - Shadow Cracking
>Crack Linux passwords using John in your Kali VM with Bridge Adapter network mode.  You will create a user and set their password.  Then you will prepare the hash file and use John to crack the hash with the Rockyou wordlist.
>#### Step 1 - Create User
>Create a user “tester” using the following command.
>```
>sudo useradd -m tester
>```
>Set the tester user password to “Password123” with the following command.
>```
>sudo passwd tester
>```
>#### Step 2 - Prepare Password List
>Unzip rockyou.txt.gz with the following command.
>```
>gunzip /usr/share/wordlist/rockyou.txt.gz
>```
>#### Step 3 - Crack the Password
>With the tester user created and the rockyou.txt file unzipped, crack the password using John.  Collect the tester user’s password into a hash file.
>```
>sudo unshadow /etc/passwd /etc/shadow | grep tester > /tmp/hash.txt
>```
>Crack the user password, might take up to 5 minutes depending on your VM resources
>```
>john --format=crypt --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hash.txt
>```

### Processes
### Services
### Cron
### Logging
### Hardening

> [!activity] Activity - Benchmarking

> [!exercise] Exercise - Benchmarking
> Using inspec, run a Linux baseline scan on the Ubuntu VM in Bridge Adapter network mode.  Pick a failed rule, research how to fix it, fix it, and re-run the inspec scan to confirm the issue you selected has been resolved.
> #### Step 1 - Install Inspec
> Download the inspec package.
> ```
> wget https://packages.chef.io/files/stable/inspec/4.18.114/ubuntu/20.04/inspec_4.18.114-1_amd64.deb
> ```
> Install inspec using dpkg.
> ```
> sudo dpkg -i inspec_4.18.114-1_amd64.deb
> ```
> Confirm successful installation by displaying inspec help menu.
> ```
> inspec -help
> ```
> #### Step 2 - Run Inspec
> Run the inspec tool to detect baseline configuration issues.
> ```
> inspec exec [https://github.com/dev-sec/linux-baseline](https://github.com/dev-sec/linux-baseline) --chef-license accept
> ```
> #### Step 3 - Research an Issue
> Using the output of the previous scan, perform the following actions: 
> 1. Select a failed rule  
> 2. Research the rule and how to fix the issue   
> 3. Describe how this issue impacts security
> #### Step 4 - Fix the Issue
> With an issue researched, perform the following actions: 
> 1. Fix the issue on the Ubuntu VM 
> 2. Rerun inspec linux-baseline scan to confirm the issue has been resolved.

## Windows
This section is organized similarly to the Linux section for consistency sake.  It covers file, authorization, user and password systems.  It also introduces some of the compelling features the operating system has that impact security.
### File System
Directory Structure
### Authorization System
Basic NTFS Permissions
Advanced NTFS Permissions
### User System
Principals (Users)
Groups
### Password System
Password Hashes
Security Accounts Manager (SAM)

> [!activity] Activity - Cracking SAM

> [!exercise] Exercise - Cracking SAM
>This task requires the use of the Windows VM as well as the Kali VM, both in Bridge Adapter network mode.  You will create a test user on the Windows VM, exfiltrate the SAM and SYSTEM files onto your Kali VM, and crack the NTLM hash of the user you created.
>#### Step 1 - Create a User
>On the Windows VM, open a command prompt as Administrator and create a user with the password “Password123”.
>```
>net user /add tester Password123
>```
>#### Step 2 - Exfiltrate SAM
>From within the Windows VM command prompt running as Administrator, pull the SAM and SYSTEM databases from the registry.
>```
>reg save hklm\sam c:\sam 
>reg save hklm\system c:\system
>```
>The files were saved to the C drive’s root directory.  Drag and drop them to your host computer.  Once on your host computer, drag and drop (again) the SYSTEM and SAM files to the Kali VM.
>#### Step 3 - Dump and Crack Secrets
>From the Kali VM, with the SAM and SYSTEM files downloaded, dump the NTLM hashes using impacket.  *Note the name of the SAM and SYSTEM files is case sensitive and we named them in lowercase.*
>```
>impacket-secretsdump -sam sam -system system LOCAL
>```
>Copy the NTLM hash for the tester user into a hash.txt file.  Remember to replace `HASH` with the hash value of your tester user as highlighted in the following screenshot.
>```
>echo “HASH” > /tmp/hash.txt
>```
>Crack the password using hashcat and rockyou.txt.
>```
>hashcat -m 1000 /tmp/hash.txt /usr/share/wordlists/rockyou.txt
>```

### Processes
### Services
### Task Scheduler
### Logging
### Registry
### Patch Management
### Anti-Malware
Signature Based Antivirus
Behavioral Based Antivirus

> [!activity] Activity - Bypassing Defender

> [!exercise] Exercise - Bypassing Defender
> Using your Windows VM in Bridge Adapter network mode, you will demonstrate an AMSI patch bypass.
> #### Step 1 - Test AMSI
> From the Windows VM, start a PowerShell terminal and prove Windows Defender is running by running the following command.  The result of the command should result in an antivirus block.
> ```
> echo “AmsiScanBuffer”
> ```
> #### Step 2 - Bypass Defender
> Navigate to Rasta Mouse’s AMSI patch.  Copy each line/block into your PowerShell terminal one at a time hitting enter in between.  You can find Rasta’s patch code in the following link. 
> https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell#patching-amsi-amsiscanbuffer-by-rasta-mouse 
> Once all lines/blocks are copied, retest to confirm that the PowerShell process is no longer hooked into Windows Defender.
> ```
> echo “AmsiScanBuffer”
> ```
> #### Step 3 - Test Other Bypasses
> Pick another bypass method from the following link and test in a new PowerShell instance.  Can you find another method that works? 
> https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell

