# Introduction 
The Attacks and Countermeasures textbook prescribes hands-on learning through practical lab work that can be accomplished on most laptop or desktop computers.  Each chapter is designed around these labs based on common cybersecurity subdisciplines.  Some of these subdiscipline topics cover multiple chapters and not all cybersecurity disciplines are included in this textbook.  The chapters introduce the fundamentals of the cybersecurity subdiscipline, alongside activities and exercises to practice the topic.  

Upon reading this textbook and performing exercises, the reader will have a strong introduction and understanding on how cybersecurity affects organizations and technologies.  Readers will develop research and critical thinking skills that support applying cybersecurity principles to new or existing technologies.  It is the hope that many will be inspired to work in cybersecurity or enhance their information technology careers by applying security principles to their respective jobs.  

## Prerequisites 
To get the most out of this book, readers should have a desire to learn about cybersecurity.  The success of security researchers often requires a deep understanding of an underlying technology and the challenge of assumptions.  Therefore, individuals seeking to learn cybersecurity must be ready to understand the fundamentals of the technology. 

Good security professionals also exhibit perseverance, determination, and the ability to overcome frustration since most work requires a lot of experimenting to get things to work.  Most of the time this includes researching other professionals' work and recreating it in a lab setting.  Sometimes this work may skip steps or have inaccuracies that are needed to get an attack or countermeasure to work.  Breaking problems down, troubleshooting, and never giving up is required to overcome these shortfalls. 

This textbook expects readers to already understand computer networking, Windows, and Linux operating systems.  Computer science students in their fourth year should have the criteria needed to be successful.  But anyone who is determined should be able to learn each topic and perform the activities and exercises throughout this book. 

## Hardware Requirements 
Lab environments are set up using virtualization technology on local computers.  Some of them require running multiple virtual machines and virtual networks locally.  Many modern laptops and desktops already have the hardware needed to successfully set up and complete the exercises throughout this textbook.  Minimum hardware requirements include the following: 

- CPU that supports virtualization (BIOS/UEFI setting) 
- ~150 GBs of free local storage (flash memory/solid state) 
- 6+ CPU cores (threaded/virtual ok) 
- 12 GBs RAM 

Devices like tablets or Chromebooks will not work for the labs.  Using external drives for storage will not work either.  Chapter 1's exercise includes instructions on setting up the virtualization technologies and machines.  All instructions assume that the reader is using a Windows computer; however, readers should be able to set up the lab environments using a MacOS or Linux computer.

## Ethics 
You will be learning real-world attacks that can cause harm if misused.  Exercises in this book are conducted against local targets where you own the systems being attacked.  You do not have permission to attack other targets without their express permission, otherwise you will be violating ethics and laws.  Some activities in this book demonstrate misconfigurations and exposed data found live on the internet.  Using such information in a malicious manner is unethical and unacceptable behavior.  If you find yourself tempted to target unauthorized third parties, their networks, or attack their systems - STOP.  Instead, consider setting up your own lab to attack, which will be increasingly rewarding as you will learn more about the subject system.  Another outlet is creating an account on HackTheBox or TryHackMe to practice your skills.

## Digital Textbook Copy and Support Files 
A complete and free digital copy of this textbook can be found on my GitHub account within the `AttacksAndCountermeasures` repository ([https://github.com/dhammon/AttacksAndCountermeasures](https://github.com/dhammon/AttacksAndCountermeasures)).  You are welcome to consume, share, and reference its contents.  Support material and files can be found within the `files` folder of the repository. 

## Copyright 
Copyright © 2024 by Daniel Hammon 

All rights reserved. 

No portion of this book may be reproduced in any form without written permission from the publisher or author, except as permitted by U.S. copyright law. 

## How to Use this book 
Each chapter and lab/exercise are independent and could be explored in any order desired.  However, chapters may refer to previous labs or chapters.  Readers are recommended, but not required, to follow chapters sequentially.  This textbook uses the following styling, formatting, and syntax examples to define and describe its content throughout. 

Commands with `<SOME_VALUE>` should be replaced with the value relative to your task and your environment.  For example, I would replace `<USERNAME>` with `daniel`.  **Keywords are bolded** and
*Important words are italicized*. 

```js
//Example block of code 
```

> [!info] 
> Callout box that describe information 

> [!tip] 
> A box that includes a tip on the technology or topic 

> [!warning] 
> Word of caution to consider when applying the subject 

> [!activity] 
> A demonstration of a topic that you may follow along 

> [!exercise] 
> Lab that you are encouraged to complete on your own 

> [!story] 
> First or second-hand story that supports the topic 

## Instructor Use 
I drafted this textbook and accompanying labs to be used in a 16-week college level computer science course.  The structure and contents can be followed in part or in any desired order to the instructor, course, or students' satisfaction.  Each chapter contains enough lecture material, content, and activities for a 3-hour session - or multiple sessions cumulatively reaching 3 hours.  I usually lecture a topic, demonstrate the exercises in class, and then assign students exercises as homework.  Activities are found throughout a chapter and are used for demonstration purposes.  They are consistent with the exercises found at the end of each chapter.  However, not all activities are exercises and not all exercises have activities.  The follow table is a recommended schedule to be used at your discretion: 

| Week | Topic                  | Assignments/Labs/Projects   |
| ---- | ---------------------- | --------------------------- |
| 1    | Introduction           | Lab 1 (workspace setup)     |
| 2    | Cryptology             | Lab 2                       |
| 3    | Network Security       | Lab 3                       |
| 4    | Network Security       | Lab 4                       |
| 5    | Endpoint Security      | Lab 5                       |
| 6    | Endpoint Security      | Lab 6                       |
| 7    | Security Systems       | Lab 7                       |
| 8    | Web Security           | Lab 8                       |
| 9    | Web Security           | Lab 9                       |
| 10   | Penetration Testing    | Lab 10                      |
| 11   | Detection and Response | Lab 11                      |
| 12   | Detection and Response | Lab 12                      |
| 13   | Cloud Security         | Lab 13                      |
| 14   | Mobile Security        | Lab 14                      |
| 15   | Summary                | Project Presentations       |
| 16   | Finals Week            | Project Presentations/Final |

The last two weeks are reserved for the final project, which is not included within this textbook.  I have small groups of students identify a research topic, prepare a research paper, and present the topic, including a live demonstration.  The last two weeks have been used for in-class presentations of the final project. 

## Chapter Summaries 
The 14 chapters within this textbook cover a wide range of cybersecurity topics and subdisciplines.  None of the chapters are comprehensive as they are meant to introduce and demonstrate the subject matter.  While they are a great introduction to cybersecurity, the chapters do not cover all cybersecurity topics. 

## Chapter 1 - Information Security 
This chapter describes some of the basic information security principles and abstractions.  It includes governance, risk, and compliance (GRC), identity and access management (IAM), and business continuity among other topics.  You will complete four exercises on setting up Virtual Box and creating the three virtual machines used in later chapters.  Most exercises in the rest of the textbook rely on the completion of exercises in chapter 1. 

## Chapter 2 - Cryptology 
Cryptology is one of the foundational concepts within information security to protect data.  This chapter covers basic cryptology consisting of cryptography and cryptanalysis.  Concepts like key space, algorithms, and steganography are described and demonstrated.  There are seven exercises including Encoding and Decoding, Key Space, Symmetric Encryption, Hash Generation, Detached Digital Signature, Steghide, and Known Plaintext Attack. 

## Chapter 3 - Network Security 
An overview of networking concepts is covered in the first half of the chapter.  It includes topics like subnetting, TCP handshake, and network address translation meant to be a refresher to the reader.  The end of the chapter describes network security concepts such as virtual private networks (VPN) and firewalls.  The three exercises in this chapter include Wireshark Packet Capture, Network Utilities, and Host and Service Discovery. 

## Chapter 4 - Network Services 
Continuing from the Network Security Chapter, this chapter examines several network protocols and services, including address resolution protocol (ARP), domain name system (DNS), dynamic host configuration protocol (DHCP), transmission control protocol (TCP), and wireless.  Each service function is explored alongside its security weaknesses.  There are six exercises within this chapter titled ARPspoof, Zone File, DNS Spoofing, DHCP Spoofing, TCP Reset Attack, and Wi-Fi WEP Cracking. 

## Chapter 5 - Operating System Security 
Linux and Windows operating systems have native security features used to safely administer access and store data.  This chapter covers topics like the file system, authorization, user system, password system, processes, services, scheduled tasks/cronjobs, logging, and hardening within Linux and Windows.  The four exercises in the chapter are Shadow Cracking, Linux Baseline Hardening, Cracking SAM, and Bypassing Defender. 

## Chapter 6 - Persistence and Privilege Escalation 
Once attackers breach a system, they usually attempt to establish persistence and then escalate their privileges to maintain further control.  Building upon some of the topics covered in the Operating System Security chapter, you will learn how post exploitation techniques are conducted and identified for both Linux and Windows systems.  This chapter also covers binary exploitation through buffer overflows.  There are five exercises including Windows Persistence With Registry, Linux Persistence With Cronjob, Windows Service Privilege Escalation, Linux SUID Privilege Escalation, and Stack Smashing the Hidden Function. 

## Chapter 7 - Security Systems 
Security professionals protecting enterprise networks use special systems to prevent and detect vulnerabilities and malicious activity.  This chapter reviews how and where attacks are waged against organizations, vulnerability management, email security, security training, intrusion detection and prevention systems, data loss prevention (DLP), and deceptive security systems.  You will perform four exercises called Breach Report, Nessus Vulnerability Scan, Snort Detection, and MySQL Honeypot,  

## Chapter 8 - Web Application Defense 
Websites and web applications are a major target for attackers, making securing and defending them crucial for the overall security of an organization.  This chapter covers web application fundamentals and defense strategies.  You will learn about protecting web servers and secure development of web applications in this chapter.  In the three exercises titled Web Server Security, Secure Coding, and DAST Scan, you will set up a web server, encrypting HTTP traffic and configuring a web application firewall (WAF).  You will then run software composition analysis (SCA), static application security testing (SAST), and dynamic application security testing (DAST) scans to identify vulnerabilities within a web application. 

## Chapter 9 - Web Application Attacks 
You learned about securing web applications in the previous chapter and in this chapter, you will discover and practice common web application attacks.  It consists of topics like web application risks, application attack surface discovery using dorks and scans, and directory busting attacks.  You will also learn how to detect, exploit, and remediate authentication, cross site scripting, and SQL injection vulnerabilities.  There are four exciting exercises in this chapter named Directory Busting, Cookie Privesc, Cross Site Scripting (XSS), and SQL Injection (SQLi). 

## Chapter 10 - Security Testing 
To ensure systems and networks are secure, regular security testing must be conducted.  The goal of such testing is to identify security weaknesses in these systems.  We explore the security testing types such as vulnerability assessments and penetration testing in this chapter.  You will also learn about frameworks, command and control systems, and connection types such as reverse shells.  The four exercises in this chapter are called SSH, Reverse Shell, Metasploitable2, and Penetration Test.  

## Chapter 11 - Forensics and Malware Analysis 
Every organization is faced with the task of identifying malicious software and conducting investigations on systems to determine if they are compromised.  This chapter introduces principles surrounding digital forensic investigations and technologies.  It also covers basic malware analysis techniques used by defenders.  The three exercises in this chapter require you to conduct a forensic investigation using Autopsy, analyze malware and to write detection rules that find it, and perform static and dynamic analysis techniques to identify if a file is malicious.  The exercise titles are Forensic Investigation, Malware Detection, and Malware Analysis. 

## Chapter 12 - Incident Response 
When a breach of security is detected, an incident response process is triggered to treat the threat and restore systems to a normal operating state.  You will learn how security events and information management (SIEM) systems are used to detect breaches.  It also covers the incident response lifecycle phases and preparation effort used in most organizations.  While there are only two exercises in this chapter, the SIEM Setup exercise covers the setup and configuration of a large system.  The other exercise, Splunk Enterprise Security, is conducted on the Splunk website and results in a certificate of completion which can be great content on a resume. 

## Chapter 13 - Cloud Security 
Many organizations have a presence on the cloud to leverage the benefits of easily setting up and scaling systems.  Most new startups rely on the cloud from the start and the demand for cloud security expertise increases every year.  This chapter covers cloud basics and how security principles apply in this abstracted environment.  You will learn how to set up, defend, and attack an AWS cloud environment within the two exercises Create and Setup AWS Account and Scout Suite CSPM.   

## Chapter 14 - Mobile Security 
Mobile applications increase, or extend, the attack surface of organizations as they seek to put their technologies in the hands of users.  Using the Android operating system and emulated environment, this chapter outlines the native security controls and risks surrounding mobile applications.  You will learn how to decompose and study a mobile application using common free tools in the two exercises Static Analysis and Dynamic Analysis.

## Acknowledgments 
All the chapter images were generated using Dall-E from [https://www.bing.com/images/create](https://www.bing.com/images/create).

A big thank you to some very special people:
- My wife and children, for the continuous support.
- My mother, for helping me edit this textbook.
- My students, for the many years of inspiration and curiosity.
- Paul Paulsson, for mentorship and friendship.
- Jason Lukitsch, for the patience and mentorship during my early security career.
- Mike Gross, for the support and encouragement to teach.
- Ippsec, for the countless hours of amazing videos.
- Professor Ahmadi, for opening my world to programming. 