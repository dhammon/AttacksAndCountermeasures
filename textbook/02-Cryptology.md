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

> [!activity] Activity - CyberChef
> CyberChef, https://gchq.github.io/CyberChef/, is the Swiss army knife of encoding and encryption available as an online webapp or a command line interface (CLI) tool.  It enables users to quickly and dynamically decode and decrypt values and supports several dozen encoding schemes with multiple configurations.  The left most pane, *Operations*, has a list of formats that can be dragged into the middle pane, *Recipe*.  The input value is entered into the upper right pane, *Input* and the output value is displayed on the bottom pane *Output*.  You can use multiple layers of formats to produce the final output.  The left pane options are written in the context as "to" or "from".  The logic used starts with the input value is converted "to" or "from".  The following screenshot shows CyberChef in action by encoding "Hello World!" to hexadecimal format.
> ![[../images/02/cyberchef_activity.png|CyberChef Hello World Example]]
> 

One researcher recently discovered how to find the AWS account number from and AWS Key ID by removing metadata, decoding the ID using base 32, then decoding the hex values to ASCII while performing a bitwise operation[^2].

>[!exercise] Exercise - Encoding and Decoding
>Encoding and decoding values is a very common when analyzing data and having the skillset benefits many security roles.  
>#### Step 1
>Try identifying each string and determine the type of encoding being used:
>- `WW91IGhhY2tlciB5b3UhIQ==`
>- `69 110 99 111 100 105 110 103 32 105 115 32 110 111 116 32 101 110 99 114 121 112 116 105 111 110 32 58 41`
>- `77 30 30 74 20 77 30 30 74`
>- `48 65 78 20 69 73 20 63 6f 6d 6d 6f 6e 6c 79 20 75 73 65 64 20 77 69 74 68 20 61 73 73 65 6d 62 6c 79`
>- `01101111 01101110 01100101 00100111 01110011 00100000 01100001 01101110 01100100 00100000 01111010 01100101 01110010 01101111 00100111 01110011`
>#### Step 2
>Now decode each string from step 1 using CyberChef https://gchq.github.io/CyberChef/.
>#### Step 3
>Again using CyberChef, encode the following string into a base 32 format.
>`Cyber Chef is an awesome tool!`
>
## Ciphers
Let's put some of the terms learned so far in this chapter to use.  There are two categorizes of encryption algorithms whose primary difference is how they handle the plaintext data being encrypted.  **Block ciphers** encrypt the plaintext in chunks of fixed characters while **stream ciphers** encrypt one bit at a time.  Each cipher types have various *modes* that have various attributes that determine the size of blocks, how keys are used, and other features.  We'll explore modes later in this chapter.

A block cipher starts with an *initialization vector (IV)* which is a random value that is attached to each block of data.  An encryption *key* and the initial block with the IV are passed to the cipher which outputs the ciphertext.  Each encrypted block is used as the IV of the next block until all blocks are encrypted.  The block size varies depending on the cipher mode being used but is usually between 64 and 128 bits.  The following diagram demonstrates the mechanics of a basic block cipher starting on the left and working towards the right.
![[../images/02/block_cipher.png|Block Cipher Diagram|500]]

The stream cipher uses a key and *use only once (nonce)* value to create a key stream and is XORed with the plaintext input to produce the ciphertext.  This process is performed continuously bit by bit until the entire data stream has been processed.  The diagram below attempts to illustrate the process of a general stream cipher.
![[../images/02/stream_cipher.png|Stream Cipher Diagram|400]]

Both cipher types support the decryption of ciphertext by using the same algorithm and key.  The ciphertext is used as the input and the output value is the plaintext message.
## Key Space
A cryptographic system relies on the encryption key remaining a secret as the other components used, such as the cipher, are assumed known.  To keep encrypted data secure it is important to use a good key value.  An encryption key is ideally long and random, also known as *entropy*, to prevent certain types of attacks that could guess the key value.  Having a random key is vital because if the generated key followed a predetermined pattern it could be narrow the possible number of keys and make it easier to crack.  Another heuristic of a strong key is its length.  The longer the key value to exponentially longer it would take to guess.  Secure keys are long and random!   Most people accept a minimum key length of 128 bits (16 bytes) and very strong at 512 bits (64 bytes).

> [!exercise] Exercise - Key Space
> OpenSSL is a command line tool available in Linux systems that can perform almost any cryptographic activity you can imagine.  It comes preinstalled on Ubuntu and can be used to generate random encryption keys of a desired length.  Start your Ubuntu VM and open a terminal.  Create a random 32, 128, and 256 key using the following commands.
> `openssl rand -base64 32`
> `openssl rand -base64 128`
> `openssl rand -base64 256`

Most encryption technologies have the ability to produce a secure key using a seed value, such as the time the key is being generated at.  A short key could be quickly guessed by checking every variation of bits in the length of the key.  Raw key values are stored as bits, which are mostly unrenderable in UTF as we learned in the encoding section of this chapter.  Because keys need to be be used as inputs, most encryption technologies expect the value of the key to follow a specific format.  This format starts with a header, then a base 64 encoded blob of the raw key value, and followed by a footer.
## Key Algorithms
The process of encrypting data and accessing it with a key that you have is an easy enough use case to grasp.  The key, referred to as a *private key* because it must be kept a secret, is used to encrypt the data and is the same key that can decrypt the data, known as **symmetric encryption** and popularized by the deprecated *data encryption standard (DES)* and the modern *advanced encryption standard (AES)*.  However, things get more complicated if you want to share encrypted data between two entities.  The party encrypting the data with a key can send the data securely to a receiving party, but how does that party decrypt the message without the key?  They of course would need to also have the key that was generated by the sending party, but how do they get that key in a secure manner?  It would be unwise to send the key in a separate message that was unencrypted and if the sending party were to encrypt the key before sending it what key do the use to encrypt the key?  Sometimes this effort is easy enough to overcome if within a trusted network or where the sender and receiver are working out of the same system.  The following graphic demonstrates the transfer of encrypted data over the internet using the same private key (black keys) held by two parties (universally known as Bob and Alice).
![[../images/02/symmetric_keys.png|Symmetric Key Encryption|300]]

> [!exercise] Exercise - Symmetric Encryption
> We'll continue the use of OpenSSL on your Ubuntu VM to complete this exercise where you will encrypt and decrypt a message using symmetric encryption.
> #### Step 1
> Open a terminal and create a plaintext file with a secret message.  
> 
> `echo "some secret message" > plain.txt`
> #### Step 2
> With the plaintext file created, encrypt the message using AES 256 encryption code block cipher mode.  You should be prompted to enter a password (key).  Note that the "-p" option displays the IV and key.
> 
> `openssl enc -aes-256-cbc -p -in plain.txt -out plain.txt.enc`
> 
> Review the contents encrypted message using the cat command and observe it is unrecognizable from the original message.
> 
> `cat plain.txt.enc`
> 
> #### Step 3
> Next, decrypt the encrypted message using the key you set in step 1.  Note that the "-d" option sets decrypt mode and the "-A" option performs a base64 buffer.
> 
> `openssl enc -aes-256-cbc -d -A -in plain.txt.enc`
> 
> If successful you should have your original message displayed!
> ![[../images/02/symmetric_exercise.png|Symmetric Exercise Result]]
> 

A major issue arises when you want to share encrypted party with anonymous users at scale.  A common example of this problem is best illustrated by a website.  The website does not know who is requesting files from the webserver but there is a need to have the requests and response payloads encrypted while traversing the internet.  Another conceptual problem arises when we realize we wouldn't want to use the same encryption key for each anonymous user; otherwise, any anonymous user would be able to decrypt requests and responses for any user defeating the purpose of using encryption to begin with.  So we need a solution that allows for the secure transfer of unique encryption keys between parties.  **Asymmetric encryption** solves this through the use of two encryption keys derived from the same mathematical function using the product of very large prime numbers popularized by *Ron Rivest, Adi Shamir, and Leonard Adleman (RSA)*.  One of the keys generated is long and is meant to keep as a secret being referred to as a *private key*.  The second key is shared with everyone and know as a *public key*.  The public key is not a secret and is offered in plaintext.  A requestor of a website requests the webserver's public key and then the requestor creates a private key.  Using the webserver's public key, the requestor encrypts their private key before sending it to the receiving webserver.  The webserver receives the private key of the requestor that was encrypted with the webserver's public key and then decrypts that key using the webserver's private key.  All future communications between the client and server use this private symmetric key to encrypt and decrypt messages.  The following graphic shows two parties using asymmetric encryption where a public key (white key) is provided to the requestor and is used to encrypt keys used in messages between the parties.
![[../images/02/aysmmetric_keys.png|Asymmetric Key Encryption|350]]

To recap, symmetric encryption uses one private key while asymmetric encryption uses a public and private key pair to encrypt a symmetric key.  Both key algorithms have their advantages over the other.  Symmetric is very fast while asymmetric is significantly slower because there is several more steps and network latencies.  However, asymmetric encryption solves the key sharing and scaling problems that symmetric has.

>[!activity] Activity - Asymmetric Encryption
>We can use OpenSSL on Ubuntu to encrypt messages using asymmetric encryption too!  After creating a public and private key pair using OpenSSL,  a message can be encrypted using the public key and then decrypted using the private key.
>
>I'll create a 1024 bit private key into a file named private.pem and display the result.  Notice the key's header and footer and that the content is in base64 encoded format.
>![[../images/02/asymmetric_activity_private_key.png|Private Key Generation]]
>Next, I create a public key into a public.pem file that pairs with the private key.  This public key will be used to encrypt messages.
>![[../images/02/asymmetric_activity_public_key.png|Public Key Generation]]
>With the key pair created I create a message in the plain.txt file and encrypt it using the public key while outputting the ciphertext into the plain.txt.enc file.  The contents of plain.txt.enc are not legible!
>![[../images/02/asymmetric_activity_encrypt.png|Asymmetric Message Encryption]]
>Finally, we can use the private.pem key to decrypt the message and display its content "hello world"!
>![[../images/02/asymmetric_activity_decrypt.png|Asymmetric Message Decryption]]

## Cipher Modes
move this to after Ciphers or make a child of ciphers
- ECB
- CBC
- GCM

> [!warning] Warning - ECB Insecurity

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
[^2]: A short note on AWS KEY ID; by Tal Be'ery; October 24, 2023; https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489