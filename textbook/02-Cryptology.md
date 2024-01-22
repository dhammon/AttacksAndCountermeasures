# Chapter 2 - Cryptology

![](../images/02/cryptology.jpg)

One of the fundamental tenants of protecting data is the with encryption.  Its use originated from the need to protect military plans hundreds of years ago.  The goal of encryption is to protect information from those not authorized to view it.  Using encryption assumes that the information will end up in the hands of those unauthorized parties.  This chapter covers the basics of cryptology and its practical use.

**Objectives**
1. Review the fundamentals of cryptography;
2. Demonstrate usage of cryptography in information technology; and
3. Understand cryptographic attacks and countermeasures.
## About Cryptology
Long ago, Julius Caesar commanded an army engaged in battle.  He and his generals would communicate with their troops who were geographically disbursed via messengers carrying battle plans.  The enemy understood this method of communication and would capture messengers and their battle plans in an effort to gain tactical advantage.  Caesar countered these interceptions by encrypting the battle plans in an effort to obfuscate should they fall into the hands of the enemy.  Thus, encryption has its roots as a military tool that protected sensitive information from unauthorized parties.

The field of **Cryptology** is the study of the creating and breaking code systems that transforms to and from useable forms.  The design of such systems is called **cryptography** and generally consists of the development of mathematical processes that result in the encryption and decryption of information.  Cryptology also includes **cryptanalysis** which attempts to undermine cryptographic efforts by *breaking* encryption and enabling unauthorized use.  Often, cryptologists study and perform both cryptography and cryptanalysis in an attempt to create secure encryption.
### Data Protection
A substantial portion of information security relies on encryption.  Those who are attempting to defend information at organizations will encrypt that data in an effort to protect it from unauthorized use.  Therefore, the use of encryption is from a defensive posture.  These security professionals and administrators ensure that sensitive information is stored and transmitted in a format unreadable by unauthorized third parties.  Some encryption is broken, some is good, while others are currently impervious to *cracking*.  These defenders will ensure the appropriate encryption technologies are used by validating the type of encryption.

Just as there are those who defend information there also exists those who seek to obtain that information through attack encryption.  They will attempt to break the encryption of protected data through cryptanalysis to reveal the unencrypted information.    

> [!note] Note - Blue and Red Team
> Defenders of information systems are referred to as *blue team* while attackers of these systems are known as *red team*.  Red teams and their members are not malicious actors and typically work on the side of an organization.  They use their attacking skills and tools in an attempt to detect vulnerabilities with information systems and report findings to the organization to fix them.  Blue team members work on the side of detection and response at an organization.  They would be able to detect attacks and respond accordingly.  Sometimes these teams work independently from one another.  When they work together it is known as *purple team*, and can be beneficial to both groups to efficiently identify issues faster.
### Encryption Goals
Encryption solves several information security issues.  It provides **privacy** by obfuscating data from unauthorized viewers.  Users of encryption can expect that their unencrypted information is not readable by third parties.  Encryption also provides **authentication** as those receiving encrypted data can be assured that the encrypted data was from a valid party by using a shared secret.  Protected information's **integrity** is validated because encrypted messages that have been altered won't pass encryption checks.  If encrypted data is altered the decryption validation process will fail.  Finally, encryption can ensure **nonrepudiation** as its use can be traced back to the data's source.  A convenient way to remember these features of encryption is through the acronym *PAIN*: (P)rivacy, (A)uthentication, (I)ntegrity, and (N)onrepudiation.
### Applied Encryption
Most people use encryption everyday and don't even realize it.  This is because secure information systems have encryption seamlessly built-in and running in the background.  For example, portable devices like laptops may have their storage media encrypted using Window's *Bitlocker* or MacOS's *FileVault*.  These drive encryption technologies transform all data written onto the storage media into unreadable content that can only become readable if the correct secret, or password, is entered.  The user of an encrypted laptop decrypts its contents when the enter their logon password!  

Another common use of encryption is during the use of browsing the internet websites.  About 85% of the internet websites use encryption by default as of January 2024[^1].  Web technologies us *transport layer security (TLS)* formally know as *secure socket layer (SSL)* which encrypts *hyper text transport protocol (HTTP)* request bodies between web servers and browsers.  The selection and use of TLS websites, also known as HTTPS where the "s" stands for secure, is automatically established by the browser and web server and the average user wouldn't even notice.  Sometimes this HTTPS encryption has an error and the browser will display a danger warning that the data could be exposed because of an encryption failure.  

Email systems use encryption seamlessly as well, at least in part.  Usually an email client will establish an encrypted connection to their email server via HTTPS or *simple mail transport protocol secure (SMTPS)*.  The email server that processes and sends the client email does so over SMTPS ensuring the email is not accessible to any intermediaries while it traverses the internet.  Then, the email's target audience uses their email client to securely download the message and its contents, again over HTTPS or SMTPS.  This works well enough for security and is seamless to the email sender and receiver.  However, the email contents are in a decrypted state while in the email servers and anyone with access to those servers can view the unencrypted email.  A less seamless email encryption method is to encrypt the contents of the email before encrypting it with the email server.  Two popular client side content encryption technologies are *secure/multipurpose internet mail extensions (S/MIME)* and *pretty good privacy (PGP)*.  These technologies allow more advanced users to ensure not even email administrators can view the contents of messages.

> [!note] Note - When to Encrypt?
> Encryption does more than protect data, it also provides a medium of trust between two parties through authentication and integrity (see PAIN).  Its important to use encryption technologies where ever you rely on information from third parties or when you want to protect data.  But where is the data that needs to be encrypted?  Data must be *encrypted at rest*, such when persisted on storage media like a hard drive.  It also must be *encrypted in transit* while being transmitted over networks through ethernet or WiFi signals.  Finally it should be *encrypted in use* like when it is being used in a computer's memory or RAM.
### Terms
There are a number of definitions to know when discussing encryption methods, technologies, and processes.  We've already covered several key terms and will use even more throughout this chapter.  The following terms will set up the base terminology when discussing how encryption works.
- **Plaintext** - the original message or content before being encrypted.
- **Ciphertext** - the message or content that is encrypted from an output of an cryptographic function.
- **Encryption** - to transform plaintext into ciphertext.
- **Decryption** - to transform ciphertext back to plaintext.
- **Algorithm** - also known as a *cipher*, is a logical or mathematical process that mutates data into a predictable format using a secret or key.
- **Key** - a secret value used in a cryptographic algorithm to provide encrypt or decrypt data.
- **Cipher Mode** - method of an algorithm that determines how much data to process at a time.

These terms will be used in this chapter and are common vernacular when discussing properties of encryption with security professionals.  As some encryption technologies is better than others, it is important to have a firm understanding of the properties that make up encryption to ensure the right technology is chosen.
## Encoding
Let's get this straight right away, **encoding** is not encryption.  However, it is worth a review as ciphertext is often not in a format that is readable or interpretable by a computer's terminal or word processor.  As some of the ciphertext values don't have a character representation they will be displayed as unusual Unicode characters or as a blank space.  But there is still a value there and systems need the ability to transmit ciphertext with noncharacters.  The solution is to encode the raw output into a format that can be used or transmitted by other systems.  Encoding is commonly used with many other systems regardless of encryption; therefor learning about it will benefit the reader beyond the scope of encryption.  

The *American Standard Code for Information Interchange (ASCII)* encoding format has 128 unique characters you are likely most familiar with.  The following table lists the character (Char) and its decimal and hexadecimal format reference.  

![[../images/02/ascii.png|ASCII Table of Characters]]
The *decimal* format is a base 10, numbers 0-9, format and each character is represented by a numeric value.  Similarly, the *hexadecimal* format is base 16, 0-9 and a-f totaling 16 characters, where all characters can be represented by some some combination of base 16 characters. Looking up the character "$" shows the decimal value 36 and the hexadecimal value 24.  There are other encoding schemes using the base method.  Another very common base encoding is *base 64* in which there are 64 characters that can be use in chunks of four characters and padded with the equal sign "=".  Base 64 characters include 0-9, a-z, A-Z, and special characters "/" and "+".  Base 64 is commonly used in HTTP because it does not include HTTP special characters like "?" and "&" that have explicit meaning in the protocol.  It is perfect for transmitting data without causing errors in the HTTP protocol.

Data is also organized in chunks of bits consisting of one's and zero's.  An 8 bit chunk can represent 2^8 or 256 unique combinations within the *Unicode Transformation Format 8 bit (UTF-8)* encoding system.  For example the UTF-8 bit *binary* value `00100100` represents the dollar sign character $.  The UTF standard goes beyond 8 bits and supports non-English language characters and other special characters like emojis. 

Each encoding type has recognizable pattern that you should develop the ability to recognize.  Having the skillset to observe a block of data and immediately see the type of encoding it uses will help you in your cyber analysis efforts.  The following table lists the encoding of "Hello World!" in various encodings we have covered, the encoding type, and an description of the hallmarks of that encoding.

| Type | Hallmarks | Example |
| ---- | ---- | ---- |
| Binary | ones and zeros | 01001000 01100101 01101100 01101100 01101111 00100000 01010111 01101111 01110010 01101100 01100100 00100001 |
| Decimal | numbers only | 72 101 108 108 111 32 87 111 114 108 100 33 |
| Hexadecimal | numbers and letters a-f | 48 65 6c 6c 6f 20 57 6f 72 6c 64 21 |
| Base64 | numbers, upper and lowercase letters, and special characters +, /, and = | SGVsbG8gV29ybGQh |

> [!activity] Activity - Cyberchef
> Cyberchef is the swiss army knife of encoding and encryption.  It enables users to quickly and dynamically enter values and decode/decrypt.

>[!exercise] Exercise - Encoding and Decoding

AWS account number from ID decoding multiple layers example
## Ciphers
- Block Ciphers
- Stream Ciphers
## Key Space

> [!exercise] Exercise - Key Space

## Key Algorithms
Symmetric Encryption
Asymmetric Encryption

## Cipher Modes
- ECB
- CBC
- GCM

> [!warning] Warning - ECB Insecurity

> [!exercise] Exercise - Symmetric Encryption

>[!activity] Activity - Asymmetric Encryption
## Hash Algorithms
Process
Types
- MD5
- SHA
- NTLM

> [!exercise] Exercise - Hash Generation

## Encryption Authentication
### Message Authentication Code
### Digital Signatures

> [!exercise] Exercise - Detached Digital Signature

## Steganography

> [!exercise] Exercise - Steghide

## Cryptanalysis
- Known-plaintext Analysis (KPA)
- Chosen-Plaintext Analysis (CPA)
- Ciphertext-Only Analysis (COA)
- Man in the middle (MITM)
- Adaptive Chosen-Plaintext Analysis (ACPA)
- Birthday Attack
- Side-channel Attack
- Brute-force Attacks
- Differential Cryptanalysis
> [!exercise] Exercise - Known Plaintext Attack

[^1]: Usage statistics of Default protocol https for websites; January 2024; https://w3techs.com/technologies/details/ce-httpsdefault#:~:text=These%20diagrams%20show%20the%20usage,85.1%25%20of%20all%20the%20websites.