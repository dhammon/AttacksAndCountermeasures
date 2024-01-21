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

Defend
Attack
### PAIN
- Privacy
- Authentication
- Integrity
- Non-repudiation
### Applied Encryption
Portable Devices
Email
Websites
### Terms
- Plaintext
- Cyphertext
- Encryption
- Decryption
- Algorithm
- Key
- Mode
## Encoding
- binary
- decimal
- ascii
- hex
- base64

Examples

> [!activity] Activity - Cyberchef

>[!exercise] Exercise - Encoding and Decoding

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

