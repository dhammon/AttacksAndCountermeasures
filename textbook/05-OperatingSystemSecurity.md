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
In the previous section we explored the ext4 file structure and suggested every file has an owner and group.  In addition every file can have *read (r)*, *write (w)*, and *execute (x)* permissions expressed for the owner, group, and *others*.  Owners are the creator or the assigned account of the file.  Any account on the Linux device can be assigned to one or more groups and a group can be assigned permissions to a file.  The last set is the others group, which apply to any other account on the system.

>[!note] Note - Self Group
>Each time an account or user is created, a corresponding default group using the account name is also created.  If an account `daniel` is created, a group named `daniel` is also created and user is automatically assigned to their like-named group.

The **permission set** for any file is displayed using the `ls -l` command.  The first 10 characters are dedicated to identifying permissions for each entity.  The first is used to label a directory with the letter `d` or `-` for file.  The next three characters identify permissions for the user.  The second set of three are for the assigned group.  And the last set of three characters define the permissions for others.  The 3rd and 4th column of the list command displays the owner and the group of the file.  The figure below illustrates the owner (daniel) and the group (dev) for the example.txt file.  It shows that daniel has read/write, dev has read, and everyone else (others) have read permission.
![[../images/05/linux_permission_set.png|Linux Permission Set|400]]
Read, write, and execute (rwx) can be set using the `chmod` command with *symbolic* or *octal* notation.  We have already covered the permission set using symbolic where the permissions are referenced using `r`, `w`, and `x`.  These same permissions can also be represented using octal, or numeric, notation.  Each permission is represented by a number as listed in the following table.

| Permission | Symbolic | Octal |
| ---- | ---- | ---- |
| Read | r | 4 |
| Write | w | 2 |
| Execute | x | 1 |
A permission set can then be referred to using the total of the octal permissions.  For example, if the user account www-data has read, write, and execute permissions on a file, the octal value is 4 + 2 + 1 = 7.  Under this notation, you can identify a symbolic set given just the octal value.  For another example, given the octal 5 you can infer that the permission set is read and execute because 4 and 1 is the only combination that gets to 5.  Symbolic notation references the permission set with the letters `u` for user, `g` for group, and `o` for others.  Octal references the user, group, and others permission sets in order of placement.  Therefore an octal permission set 754 means the user has `rwx`, the group has `rx`, and the other has `r` only.  Consider the following code block.

```bash
chmod ug+rwx example.txt
chmod o+r example.txt
chmod 777 example.txt
```

The first chmod command sets the user and group of example.txt to read, write, and execute permissions.  The second command sets the other permission set to read only while the last command uses octal notation setting read, write, and execute permissions for the user, group, and other.

> [!warning] Warning - Octal 777 Permission Set
> Setting read, write, and execute for all users and groups on a system is considered an insecure practice.  Many Linux systems will highlight the file and change the name color to red to warn of the setting.

There is also a special permission, called the *sticky bit*, that can allow an executable file to be ran as the file's owner or group.  In the case of the file the file is modified using chmod and the **set user ID (SUID)** is set and the symbolic notation execute bit `x` is replaced with an `s` for the user permission set.  I might look like `rws` instead of `rwx`.  Similarly, **set group ID (SGID)** is set in a similar fashion.  In either relative case, this allows the executable file to be ran by anyone as the owner or group.  SUIDs and SGIDs files can be helpful to Linux administrators when elevated access is needed only for a specific executable.  We will explore how SUID/SGIDs can be abused to achieve privilege escalation in the next chapter.
### User System
Linux users are created and modified by a system administrator using the `useradd` and `usermod` commands.  Users are usually assigned a folder of the same name under the `/home` directory where they are the default owners.  As mentioned earlier, they are also assigned into a group of the same username but they can be added to any other group.  In previous activities we demonstrated adding a user to the sudo group using the usermod command.  Users can be assigned an interactive logon shell, but they don't have to be.  A user account that doesn't have an interactive shell or home folder is referred to as a *system account*.  These user accounts are used for applications and can still have permissions granted to them for files on the system.  The following command creates a new user named `daniel` on the system.

```bash
useradd -m daniel
```

Any user can be added to any number of groups.  The power of groups comes to light when having to manage many users on a system.  The assignment of users to groups and groups to files allows administrators to organize and streamline the management of file access.  The following command creates a new group `dev` for which users can be assigned to.

```bash
groupadd dev
```

Managing users and groups by file promotes the separation of access supporting the security of the system.  For example, a web application running as the system user www-data may not need the permissions to read to files outside the www folder.  Should the web application running as the www-data user ever be compromised, its impact will be minimized to the files it can read.
### Password System
All interactive user accounts should have a strong password to logon the system and begin using files.  This means that passwords must be set and stored within the Linux system to ensure security through authentication.  Linux does not store user passwords in plaintext.  Instead, passwords are hashed and then stored on the system.  When a user logs in, or re-authenticates, their plaintext password is hashed.  The system takes the user supplied password hash and compares it against the stored password hash set for the user.  If the hash values match, the user is authenticated; otherwise, their access is denied.

The hashed passwords used to be stored, along side user information, within the `/etc/passwd` file.  This file contains information such as usernames, shell settings, home folders.  Hashed passwords were removed from this file because the other permission set had read permissions allowing anyone to see the hash passwords.  The danger of exposing a hashed password is that an attacker could attempt to crack it offline taking as much time as they need to do so.

Nowadays, the hashed password is stored in a file `/etc/shadow` that is only readable, and writable, by the root user.  Doing so limits the opportunity for a hash password to be leaked and cracked by an attacker.  The shadow file lists each account's username and hashed password separated by a colon.  Depending on the hash algorithm used, the hash password is delimited by dollar signs into three segments.  The first segment defines the algorithm type, the second segment is a salt, and the last segment is the hashed password.  A salt is a random unique string that is added to the user password when hashed.  This method ensures any two users with the same password will have different hashes.  It also slows down an attacker's computation capacity when attempting to crack many user's hashed passwords at once.  It also eliminates the risk of *rainbow password* attacks where attackers use pre-computed hash lists to crack a target hash password.

> [!activity] Activity - Shadow Cracking
> Hashed passwords can never be *unhashed*.  However, an attacker that has the hash can attempt to recreate it using bruteforce or dictionary methods.  Bruteforcing password hashes usually means computing the hash of foreach character combination and comparing them against a target hash until a match is found.  This becomes prohibitively expensive in time and energy the longer and higher entropy (random) a password is.  Alternatively, in a *dictionary attack*, a list of common passwords are hashed one at a time and their output is compared to the target hash.  A password is cracked when there is a match as the attacker knows the guessed password that was hashed.  
> 
> Using the Kali VM, I will create a test user and assign them a password.  Then I will prepare a hash file that can be used with the cracking tool John to crack the password using the rockyou password list.
> 
> First I launch a terminal and create a user tester using the following command.
> ```bash
> sudo useradd -m tester
> ```
> ![[../images/05/linux_activity_crack_useradd.png|Creating the User Tester|600]]
> With the user created, I set their password to the weak and all too common "Password123" using the passwd command.
> ```bash
> sudo passwd tester
> ```
> ![[../images/05/linux_activity_crack_pass_set.png|Setting Tester User Password|600]]
> Now that the vulnerable user is created I create a hash file using John's unshadow command.  This utility combines the passwd and shadow files into a new file that is compatible with John.  I pipe the result to grep to pull the line that has our tester victim then redirect that line into a file in the tmp folder called hash.txt.
> ```bash
> sudo unshadow /etc/passwd /etc/shadow | grep tester > /tmp/hash.txt
> ```
> ![[../images/05/linux_activity_crack_unshadow.png|Creating Unshadowed Hash File|600]]
> I'll launch a dictionary attack which requires a list of passwords.  Kali has many password lists already installed that I can use.  My favorite is the rockyou.txt list which consists of around 14 million passwords leaked from a LinkedIn breach many years ago.  The file is compressed so I use the gunzip utility to extract the list.
> ```bash
> sudo gunzip /usr/share/wordlists/rockyou.txt.gz
> ```
> ![[../images/05/linux_activity_crack_rockyou.png|Extracting Rockyou Password List|600]]
> The last step is to launch John against the hash file stored in the tmp directory.  I'll set the format to crypt as this is the format or algorithm used by Kali to hash passwords.  It takes about 5 minutes to complete on my virtual machine but could be much faster on a host computer with a GPU.
> ```bash
> john --format=crypt --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hash.txt
> ```
> ![[../images/05/linux_activity_crack_result.png|Cracked User Password Using John|600]]
> After the password is crack, John displays it alongside the user name!


>[!exercise] Exercise - Shadow Cracking
>Crack Linux passwords using John in your Kali VM with Bridge Adapter network mode.  You will create a user and set their password.  Then you will prepare the hash file and use John to crack the hash with the Rockyou wordlist.
>#### Step 1 - Create User
>Create a user “tester” using the following command.
>```bash
>sudo useradd -m tester
>```
>Set the tester user password to “Password123” with the following command.
>```bash
>sudo passwd tester
>```
>#### Step 2 - Prepare Password List
>Unzip rockyou.txt.gz with the following command.
>```bash
>gunzip /usr/share/wordlist/rockyou.txt.gz
>```
>#### Step 3 - Crack the Password
>With the tester user created and the rockyou.txt file unzipped, crack the password using John.  Collect the tester user’s password into a hash file.
>```bash
>sudo unshadow /etc/passwd /etc/shadow | grep tester > /tmp/hash.txt
>```
>Crack the user password, might take up to 5 minutes depending on your VM resources
>```bash
>john --format=crypt --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hash.txt
>```

### Processes
Any time an executable or command is ran on a Linux system, at least one new process will be created.  **Processes** are applications that have been loaded into memory by the system and are processed by the CPU.  The CPU will interact with the process' memory space to execute its machine code as designed.  When the process is created, it is given a *process id (PID)* which is a 5 digit number unique to any other running process on the operating system.  A process can invoke any number of additional applications which in turn create new processes.  These process invoked processes are attributed to the calling process known as the *parent PID (PPID)*.  The subordinate process to the parent is referred to as the *child process*.  Because commands or applications are ran under the context of a user, each process inherits the permissions of that particular user.  Each process user context is identifiable when enumerating processes running on a system.

> [!note] Note - Process Permissions
> The principle of least privilege should apply with processes because they can be abused to escalate privileges accessing system resources it should be allowed to.

> [!activity] Activity - Navigating Processes
> Processes can be created, observed, and stopped using pre-installed Linux commands.
> 
> Using the Ubuntu VM, I'll run the watch command to monitor changes to the `home` folder using the ls command.
> ```bash
> watch ls /home
> ```
> ![[../images/05/linux_activity_proc_watch.png|Running Watch and List Processes|600]]
> Because the command is continuously running, it is safe to assume there is a process that is running.  I can view the process details using the `ps` or process command with the options `auxwf`.  These options will show every option running and display in a tree mode for parent to child reference.
> ```bash
> ps auxwf
> ```
> ![[../images/05/linux_activity_proc_ps.png|Running Process Tree]]
> The process command displays my running `watch` command with a PID 4610.  The command shows that the process is a child process of a bash command, since it is running in a terminal.  I could stop the command in the window that it is running with `CTRL+C` but I could stop the process using the `ps` command.
> ```bash
> kill -9 4610
> ```
> ![[../images/05/linux_activity_proc_kill.png|Kill Running Process|600]]
> Once the kill command completes, the terminal where the watch command was running returns to bash with a "Killed" message.
> ![[../images/05/linux_activity_proc_killed.png|Killed Process Result|600]]
> Another useful tool is the `top` command which will display all running processes.  You can sort by resource dynamically and the tool output refreshes every second.
> ```bash
> top
> ```
> ![[../images/05/linux_activity_proc_top.png|Running Top Command|600]]
### Services
Processes, or applications, that continuously run in the background waiting for an event or doing a task are known as **services**.  A *daemon* is a long running process that is running in the background and is often used to describe a service.  But a service is much more than a long running process in the background as the system is specifically configured with a service system that defines a how the service will behave and its other attributes.  Therefore services are daemons but not all daemons are services - a service contains at least one daemon.

>[!activity] Activity - Exploring Systemd
>Linux manages services using the `systemd`, or system daemon, to manage the services on the device.  The service files are located in the `/etc/systemd/system/` directory as demonstrated in the following command.  Many of these files use symbolic links to reference other areas of the file system where the service file resides.
>```bash
>ls -la /etc/systemd/system/
>```
>![[../images/05/linux_activity_system_cat.png|Systemd Files|600]]
>One of the service files I observed in that etc folder was the Avahi service.  Service logs are stored in a journal maintained by systemd and can be queried using the `journalctl` service.  The following command shows the logs of the Avahi service.
>```bash
>sudo journalctl -u avahi-daemon
>```
>![[../images/05/linux_activity_journal.png|Service Logs from Journalct|600]]
>Another method for listing services is to use the built-in `systemctl` tool.  The following command lists all the services available on the Ubuntu VM.
>```bash
>systemctl --type=service
>```
>![[../images/05/linux_activity_systemctl.png|Systemctl List of Services]]
>I see that our Avahi is one of the services listed here.  It shows a status of loaded, active, and running.  We can explore the service status and logs using the systemctl command as well.
>```bash
>systemctl status avahi-daemon
>```
>![[../images/05/linux_activity_avahi_service_status.png|Systemctl Status of Avahi Service|600]]
>Of note is the loaded path of the service.  This path references the file of the Avahi service which can be examined further using the concatenate command.  I pipe the output of the cat command to grep and filter out any comments in the file for sake of brevity.
>```bash
>cat /lib/systemd/system/avahi-daemon.service | grep -v '#'
>```
>![[../images/05/linux_activity_avahi_service_file.png|Avahi Service File|600]]
>This file represents the configuration of the service.  All that is needed to create, or modify, a service is a file like this one in the systemd directory.  Of particular interest is the `ExecStart` value which shows the path to a system binary called avahi-daemon.  This binary is what is actually running in the background for the service.
>

Should an attacker gain direct or indirect control of the service referenced executable in its executable path, they will hijack the service.  Some services require elevated permissions to run effectively and if vulnerable to hijacking could allow an attacker to escalate their privileges.  Another abuse is to use the native system to establish persistence which will be covered in later sections.  Such attacks can be caused if the executable is modifiable by the attacker's account.  It can also be accomplished indirectly should the service executable use other executables that are in the attacker's control.  One last common misconfiguration is to grant access to modify service files allowing a malicious actor to change the executable that would be ran.
### Cron
The **cron** Linux system is used to schedule jobs, or *cron job*, ran by users and the system.  It is used to run binaries or scripts on a regular reoccurrence as defined by the cron folder the executable resides in or through the cron table, or *crontab*, file which allows custom jobs.  The crontab file is a configuration file available for every user on the system, including the root user.

> [!activity] Activity - Preparing Cronjobs
> I can create a cron job by editing the cron table file.  Cron comes with the built-in crontab command and specifying the `-e` option for editing.
> ```
> crontab -e
> ```
> This launches the cron table file into the editor of my choosing which can be modified with a special pattern to identify the frequency the job will run and the path to the executable.  My favorite website to create schedules is https://crontab.guru.  I'll add the following entry into my crontab file.  `5 4 * * sun` will run the `cat /etc/passwd` command at 4:05 every Sunday.
> ```
> 5 4 * * sun cat /etc/passwd
> ```
> Using the crontab command with the `-l` option to list the file I can see all the cronjobs scheduled for my user.  Again I use grep to filter out any comments within the file.
> ```
> crontab -l | grep -v '#'
> ```
> ![[../images/05/linux_activity_cron.png|Crontab List User Cronjobs|600]]
> The system, or root user, cronjobs can be listed as well from the `/etc/cron*` directories.  Binaries and scripts placed in these folders will be ran by root in the respective timeframe the folder describes. 
> ```
> ls -la /etc/cron*
> ```
> ![[../images/05/linux_activity_cron_list.png|Cron Folder List|600]]
> The logs for cron activity is found within the `/var/spool/cron/crontabs` file but it is only accessible by root.  It is most helpful when diagnosing or troubleshooting cron activity on a system.

Similar to services, cron job executables can be hijacked by attackers using the same methods.  It is important to ensure the executable that is used in a cron job is secured from modification by unauthorized parties.
### Logging
The results, output, and errors generated through applications, services, and daemons are aggregated within log files.  Log files can be very useful to administrators and security professionals when troubleshooting, monitoring, or auditing systems.  Administrators can review log files which can often include the results or error messages on a system applications.  This data can be used to inform the administrator on issues the application might be having that can often lead to a resolution.  Security professionals can use system logs for monitoring and auditing purposes.  Log entries can inform security members when an application has an anomalous security event that could indicate a compromise.  The logs are also useful during investigations to identify when certain activity occurred; enabling the security team to create a timeline of events among other insights.

Logs can be categorized into system and application types.  System logs usually include entries that are related to the operating system and its core components.  *Syslog* standardizes the logs from a system into a structure form that can be centralized and sent over a network for many systems.  Daemon message, or *dmesg*, logs is another standardization for applications that run in the background.  Both syslog and dmesg logs are typically kept in dedicated files that several applications feed into.  Application logs, however, are dedicated for a specific application.  For instance, an Apache web server includes access and error log files in a dedicated application log folder separate from other application logs.

> [!activity] Activity - Linux Log Files
> Log files are commonly stored withing the `/var/log` folder.  There we can see syslog, dmesg, and application logs.  The following command lists the files within the log folder.
> ```
> ls /var/log
> ```
> ![[../images/05/linux_activity_log_list.png|Linux Log List|600]]
> I can use cat or head commands to view the log entries.  In the first line of the `syslog` file we can see a timestamp, application name, and event description.
> ```
> sudo head -n 1 /var/log/syslog.log
> ```
> ![[../images/05/linux_acitvity_log_head.png|First Line of Syslog|600]]


The format and contents of logs can vary but they usually include common useful information such as, but not limited to, timestamps, user information, and description.  Each entry is referred to as an *event* and logs are rotated on the system by size.  Once a log file exceeds a pre-set capacity limit it is zipped and moved into a new numbered file by the logging system `logrotate`.  After a threshold of log files has been met the logging system will delete the oldest file and start a new log file - rotating the log data.   Logrotate will ensure any file ending in `.log` within the `/var/log` folder will follow these rules.
### Hardening
Linux systems can be exposed to security risks not only by insecure software but also through misconfigurations of the system.  Beyond the vulnerabilities a system might have, it can also be ill-equipped to handle security threats.  **Hardening** a system is the act of ensuring the prevention and detection of security threats.  The act of hardening a system reduces the likelihood and impact of security threats and is a standard practice for individuals serious about keeping systems secure. 

The following list in no particular order details common hardening activities:
- **Patch Management** - Code maintainers of operating systems and applications make periodic updates to their technologies to improve features, performance, and security vulnerabilities.  The availability of software and its current versions can be maintained centrally within repositories such as the *advanced package tool (apt)*.  Updating software can eliminate known vulnerabilities; however, implementing a system to automate the installation of security updates improves the security posture of a system.
- **Logging** - As discussed in this chapter's section covering logging, enabling logs is a good security practice as it benefits the monitoring and auditing of security events.  Ensuring that logs are enabled, and ideally centralized into another system, strengthens the overall security of a system. 
- **Disabling Services** - We've already covered how services can be a vector for persistence and privilege escalation but they can also provide initial access to a system.  A network service is a service that listens on an open socket on the device accepting network connections which can provide an opportunity for remote access.  Ensuring system services, both internal and network services, decreases the overall attack surface of a system and reduces security risks.
- **Removing Applications** - Popularized with the term *bloatware*, removing unneeded or unnecessary software also can reduce security vulnerabilities.  We should resign the fact that all software has vulnerabilities whether they are known or not, so removing unneeded software will reduce the total amount of vulnerabilities giving system administrators less to have to maintain.
- **Access Management** - System administrators are usually responsible for the creation, maintenance, and removal of accounts on a system.  The user system and authorization systems discussed in this chapter cover the importance and the security benefits of these systems.  Removing unneeded accounts and reducing permissions to least privilege are great security practices to reduce opportunities for abuse.  Administrators should conduct regular audits of these systems to ensure tight security is maintained.
- **Secure Configurations** - Reputable software running as services usually provide guidance on the responsibilities for administrators to ensure its secure configuration.  Ideally only the services with well tested configurations are deployed and it is up to administrators to ensure the standards are maintained over time.  Administrators should ensure other security systems on the device are also enabled and configured correctly, such as host firewalls and application control software like app armor. 

> [!activity] Activity - Linux Baseline Hardening
> There are several tools and standards that can be used to regularly test or audit the security posture of a systems.  These standards are usually referred to as *baselines* and are collections of rules for a particular technology.  Chef, a popular automation tool and framework, created the tool *inspec* which comes with a set of baselines that can be used to audit the security settings of a system.  In the following activity I'll demonstrate the use of inspec against the Ubuntu system to identify configurations that can be altered to improve the security of the system.
>  
>  I start the Ubuntu VM in bridge adaptor network mode and open a terminal to install inspec.  The tool's is available in Debian software package file (.deb) and can be downloaded using the built in wget utility.
>  ```
>  wget https://packages.chef.io/files/stable/inspec/4.18.114/ubuntu/20.04/inspec_4.18.114-1_amd64.deb
>  ```
>  ![[../images/05/linux_activity_inspec_download.png|Download Inspec DEB File|600]]
>  Once downloaded I initiate the installation using the dpkg command.
>  ```
>  sudo dpkg -i inspec_4.18.114-1_amd64.deb
>  ```
>  ![[../images/05/linux_activity_inspec_install.png|Installing Inspec|600]]
>  After a few seconds the software is installed and is ready to be used.  Inspec must be fed a compliance ruleset to be ran against our system.  I will use Dev-sec's linux-baseline ruleset in this demonstration.  The following command executes the linux-baseline while accepting the standard license terms from Chef.
>  ```
>  inspec exec https://github.com/dev-sec/linux-baseline --chef-license accept
>  ```
>  ![[../images/05/linux_activity_inspec_scan.png|Inspec Linux-Baseline Scan Result|600]]
>  After about a minute of scanning, Inspec returns a list of results.  As shown in the screenshot above, green rules with a checkmark indicate a rule that has passed with a secure setting.  The rules are collected into groups, called `controls`, with the a naming syntax os-##.  The first rule in the control os-02 reads "File /etc/shadow is expected to exist" suggesting that the shadow file is expected on the system.  If the shadow file did not exist we could expect this particular rule to fail which would then display in red with an "x" instead of a checkmark.  Scrolling down the report I can observe some failed rules as shown below.
>  ![[../images/05/linux_activity_inspec_fail.png|Inspec Failed Rules|600]]
>  The section os-05 has some passed and failed rules.  When a rule fails, Inspec informs us why it failed and offers the setting needed to pass the rule.  The first failed rule "login.defs UMASK is expected to include "027" fails with the comment "expected "022" to include "027"".  Don't worry if you don't know what login.defs is or what the UMASK setting is used for, that is what Google is for!  System administrators would take these rule violations and research how to correct them then apply changes needed.  Once they have been applied, Inspec should be re-ran to confirm the solution applied worked.  Many times a solution does not fix the issue and additional efforts are needed, so re-testing is an important step in any vulnerability or misconfiguration management system.
>  
>  The very end of the report provides us with summary statistics of the number of rule ran, skipped, passed, and failed.  Such summary statistics are beneficial as they can be compared between systems to identify which systems have the most violations or security risk.  Administrators can then concentrate their efforts on those systems with the most risk making the biggest positive impact to security.
>  ![[../images/05/linux_activity_inspec_summary.png|Inspec Summary Statistics|600]]


> [!exercise] Exercise - Linux Baseline Hardening
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

