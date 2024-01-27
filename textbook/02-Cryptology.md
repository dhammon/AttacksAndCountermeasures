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
Let's put some of the terms learned so far in this chapter to use.  There are two categorizes of encryption algorithms whose primary difference is how they handle the plaintext data being encrypted.  **Block ciphers** encrypt the plaintext in chunks of fixed characters while **stream ciphers** encrypt one bit at a time.  

A block cipher starts with an *initialization vector (IV)* which is a random value that is attached to each block of data.  An encryption *key* and the initial block with the IV are passed to the cipher which outputs the ciphertext.  Each encrypted block is used as the IV of the next block until all blocks are encrypted.  The block size varies depending on the cipher mode being used but is usually between 64 and 128 bits.  The following diagram demonstrates the mechanics of a basic block cipher, *cipher block chaining (CBC)*, starting on the left and working towards the right.
![[../images/02/block_cipher.png|Block Cipher Diagram|500]]

The stream cipher uses a key and *use only once (nonce)* value to create a key stream and is XORed with the plaintext input to produce the ciphertext.  This process is performed continuously bit by bit until the entire data stream has been processed.  The diagram below attempts to illustrate the process of a general stream cipher.
![[../images/02/stream_cipher.png|Stream Cipher Diagram|400]]

Both cipher types support the decryption of ciphertext by using the same algorithm and key.  The ciphertext is used as the input and the output value is the plaintext message.
## Cipher Modes
Block ciphers have various *modes* that have various attributes that determine the size of blocks, how keys are used, and other features.  These modes of operation are algorithms that the cipher uses to encrypt data.  They detail how the cipher encrypts or decrypts each block of data through the use of the initialization vector (IV) described earlier in the chapter.  Cipher modes vary in block size, how they pad blocks that don't meet the size, and how they encrypt each block of data.  The following modes are very common but there are several modes that exist not covered in this text.  Some modes are more secure than others but may have tradeoffs in features and resources.

The **Electronic Code Book (ECB)** mode is an older mode that was widely used and recommended until certain flaws became apparent by the cryptology community.  One of the simpler modes, it takes each block and encrypts them separately using a key and works very fast consuming less resources than other cipher modes.  It is not recommended to use any longer.

> [!warning] Warning - ECB Insecurity
> Because each block is encrypted individually using the same key it lacks diffusion and patterns emerge in the ciphertext that could enable cryptanalysis to decipher parts or all of an encrypted file.  The most famous visual example of this is the encryption of the Linux Penguin using ECB. [^3]  The image on the left is the unencrypted version of the file.  The middle image is encrypted using ECB while the last image is encrypted using a modern encryption mode.  Can you spot the issue with using ECB?
> ![[../images/02/ecb_encryption.png|Linux Penguin Encrypted using ECB]]
> Remember this image the next time you are tempted to use ECB to encrypt data so you avoid using an insecure cipher mode!

Another older cipher mode, **Cipher Block Chaining (CBC)**, is very popular and commonly found in use of information systems.  It is secure enough and encrypts blocks of data using an initialization vector and XOR'ing (inversing) the encrypted blocks to be used to encrypt the next block.  The block cipher diagram referenced in the Cipher section of this this chapter is an example of how this algorithm operates.  Modern information systems using block ciphers should choose the **Galois/Counter Mode (GCM)** operation as it provides the most security, currently.  It encrypts each block with a counter, or IV, then XORs the plaintext.  GCM offers all the features of modern cryptography including authentication.  
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
## Hash Algorithms
So called *one way functions*, a **hash algorithm** takes an input and generates a cryptographic output value.  This fixed character length value will produce the same value given the same input.  Good hash algorithms will create a very different hash output, or *digest*, with even the smallest change to the given input.  Speed is also an indication of a good hash algorithm as it makes it more practical to use.  Unlike typical encryption, hash algorithms should not have a mathematical way to turn the hash value back into plaintext value - there is no way to "unscramble the egg".  The diagram below depicts the general process of inputting a message into an hash function and yielding a hash value as an output.
![[../images/02/hash_function.png|Hash Use Process|500]]

The properties of a the hash process have a proven security value to them.  Hash values provide a method to ensure integrity of a file or message.  If the user knows the original hash value of a file or message, they can generate another hash on a received message to verify it matches the original version.  Hash algorithms are also useful to authentication login systems as it provides a means to avoid having to store a password in plaintext or encrypted.  If a password is stored encrypted or in a raw value it runs the risk of one day being compromised.  Modern authentication systems don't store passwords but rather store a hash value of the password.  When a user logs into that system their entered password is first passed through the hash algorithm and the hash value is then compared to the hash value stored in the database.  If the two match, then the user can be authenticated.

Not all hash algorithms have equal security value.  Some hash algorithms have been proven to allow *collisions*, where more than one input can create the same hash value.  Such algorithms should be avoided if concerned about security.  While hash values, or hashes, can't be returned to their original values, there are tactics where the original input can be determined.  This is accomplished by passing values through the hash algorithm and comparing the output hash value to the subject hash value attempting to be decoded.  If they match then the guessed value is the implied original value.  As you can imagine, it takes many guesses to *crack* a hashed value.  We will explore tools and experiment with hash cracking later in this textbook.

There are many cryptographic hash algorithms available for use.  While we won't cover all of them, we will review a few of the more popular or common ones.  The **MD5 message-digest algorithm** produces a 32 character, 128-bit, hash value.  It is very fast and has been used since the early 90's.   However, in 2010 it was proven to be vulnerable to collisions and therefore should not be used for critical security operations.  Another very popular group of hash algorithms are the **secure hashing algorithm (SHA)** family.  It is derived from MD5 and has various length options.  The commonly used SHA-1 has 40 characters, 160 bit, and was discovered to be susceptible to collisions in 2017 by Google researchers.  It is not uncommon to still find SHA-1 being used within information systems but its use should be avoided in favor of the SHA-2 version.  This version supports multiple bit length options 224, 256, 384, or 512.  The larger the bit length the more secure, but at a sacrifice of time it takes to compute the value.  The current recommendation is to use SHA-256 or SHA-512 for secure operations.

>[!activity] Activity - Digest Verification
>Let's demonstrate the use of MD5 hash in Linux to prove the integrity of a message.  Using an Ubuntu VM, I'll open the terminal and create a message in a file called message.txt.
>![[../images/02/activity_01_message.png|Create Message]]
>We can use the md5sum utility to determine the MD5 hash digest of the message.  The command outputs a 32 character value.  We could re-run this message on any computer and get the exact same result.
>![[../images/02/activity_01_hash.png|MD5 Hash of Message.txt]]
>Now, replace the message.txt file with a slightly different message and calculate the digest.  Notice the value is greatly different from the original!
>![[../images/02/activity_01_rehash.png|Change Message and Rehash]]

Microsoft uses hashes to convert and authenticate Windows operating system passwords.  In the 1980's they developed the LAN Manager authentication scheme and its very insecure hash algorithm of the same name, **LM**.  It was based on now deprecated **Data Encryption Standard (DES)** algorithm which produces only 48 bit digests.  LM curtails the passwords to a maximum 14 characters, converts them to uppercase, encodes and pads the value, then splits the output into two 7-byte strings.  These strings are used to create DES values encrypted with a key that was published by Microsoft.  This algorithm erodes most of the security of having a long and high entropy (random) password and is usually easily cracked.  I would instruct the reader to ensure any of the systems they are responsible for maintaining the security of to avoid LM use; however, Microsoft has done a good job of making this algorithm backwards compatible and to this day its use is technically feasible.

Learning from the lessons of LM, Microsoft developed **New Technology LAN Manager (NTLM)** and later improved it and published a second version, *NTLMv2*.  The NTLM value is based on MD4 and used in the deprecated, yet backwards compatible, NTLM authentication process.  It has since been replaced with the Kerberos system originally developed by MIT.  We will explore these authentication processes later in this book.  For now, be aware of the evolution of hash algorithms and their practical use within authentication systems.

> [!exercise] Exercise - Hash Generation
> In this task you will create hash digests using Ubuntu's native md5sum and sha256sum tools.
> #### Step 1
> Create a message in a new file that we will take the hash value of.  Open your terminal on your Ubuntu machine and enter the following command.
> `echo "Tamperproof Message: crypto is the coolest!" > message.txt`
> #### Step 2
> For this step you will take the MD5 and SHA-256 values of the created file from the previous step.  Enter the following commands in the directory where message.txt resides
> `md5sum message.txt`
> `sha256sum message.txt`
> Notice the difference in the digest length between MD5 and SHA-256.
## Encryption Authentication
Encryption can be used to authenticate a sender or receiver of data, even data that is in plaintext!  The methods of accomplishing this also have the added benefit of ensuring the integrity of the data.  In the following section we will explore how a receiver of a message can authenticate the sender of the data through *message authentication code (MAC)* symmetric keys.  Similarly, this same task can be accomplished using asymmetric keys via a *digital signature*.  Both of these methods leave the message in plaintext, so it does not provide any confidentiality or privacy.
### Message Authentication Code
A bi-directional conversation between two parties can use **Message Authentication Code (MAC)**, sometimes referred to as *authentication tag* or *keyed hash*, to ensure the integrity and authenticity of each other.  MAC provides assurance that the sender and receiver were the creators of the messages being sent as they both share a private key used to encrypt and decrypt a hash of the message.  If the message is altered in any way, even by one bit, the decrypted hash digest won't match and the respective party will know that the message had been altered.  The MAC is a short piece of information that is constructed from a hash function *hash-based message authentication code* or block ciphers like *Galois/Counter Mode (GCM)* and sent along with the plaintext message, usually as a file or text.  To demonstrate this, the following diagram shows a message sender creating a MAC with a private key and sending it to a receiver who also has the private key which can be used to inspect the attached MAC to confirm the integrity of the message and authenticate the sender.
![[../images/02/mac_diagram.png|MAC Sending and Receiving|600]]

### Digital Signatures
If the authentication of a message sender, the integrity of the message, and the repudiation assurance that the sender sent the message is needed, while avoiding the use of transferring private encryption keys, a **Digital Signature (DS)** can be used.  The DS has the advantage of sending the message along with a public key so that any receiver of the message can use the public key to verify the message and sender.  This use case allows for the single direction of communication from the sender to the receiver, limiting the receiver's ability to respond in kind.    DS can be attached or detached, meaning they can be embedded as part of the message (attached) or the signature can be its own separate file (detached).  In this diagram the sender (on the right), creates a digital signature and sends it with the public key of the key-pair to the receiver (on the left).  The receiver uses the public key that was attached to the message to verify the signature that was included with the message.
![[../images/02/ds_diagram.png|Digital Signature Sending and Receiving|600]]

> [!exercise] Exercise - Detached Digital Signature
> Debian based Linux systems usually come pre-installed with GNU Privacy Guard (GPG) that offers the ability to create digital signatures.  You will use your Ubuntu VM in this exercise to create a detached DS and verify it.
> #### Step 1
> Acting as the sender of the message, we will create a key-pair using gpg via the following command.  Once the command is ran, you are prompted to enter a name and email address.  You will also be asked to enter and verify a password for your key ring that is created.  Upon successful execution a public key is created along with an entry in the system's key ring.
> `gpg --gen-key`
> ![[../images/02/lab_ds_gen_key.png|GPG Key Generation]]
> #### Step 2
> We will create our message we wish to sign using the following command.
> `echo "Message integrity and authentication are very cool" > message.txt`
> ![[../images/02/lab_ds_message.png|Create Message to Sign]]
> #### Step 3
> With the key-pair and message created we are ready to digitally sign it using GPG.  The following command will output a message.txt.sig as a detached separate file from the original message.txt.  Upon enter the first command you will be prompted to enter your password in order to access the key ring.  The second command displays the contents of the signature, note it is a public key!
> `gpg --output message.txt.sig --armor --detache-sig message.txt`
> `cat message.txt.sig`
> ![[../images/02/lab_ds_signature.png|Detached DS Creation]]
> #### Step 4
> The message and the signature are now ready to be sent.  You can pretend to send both files to another party.  When the receiver gets your message and detached signature, they will need to verify that the message has not been altered and that it was really you that sent it.  The receiver will use GPG with the verify option to confirm the message in the following command.  GPG will output a "Good signature" message upon successful validation.
> `gpg --verify message.txt.sig message.txt`
> ![[../images/02/lab_ds_verify.png|GPG Verify DS and Message]]
> #### Step 5
> Try altering the message.txt content slightly and then re-run the GPG verify command and then answer the following questions:
> - What is the output of the validation?  
> - Are you notified that the signature is bad?  
> - Explain what this means to the receiver of a message with a unverified or bad signature.  
> - What are the implications?
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
[^3]: Block cipher mode of operation; Wikipedia; January 2024; https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation