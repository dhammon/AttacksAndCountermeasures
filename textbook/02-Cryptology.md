# Chapter 2 - Cryptology

![](../images/02/cryptology.jpg)

One of the fundamental tenents of protecting data is encryption.  The use of encryption originated from the need to protect military plans hundreds of years ago.  The goal of encryption is to protect information from those not authorized to view it.  Using encryption assumes that the information will end up in the hands of those unauthorized parties. The encrypted information is unreadable to those without a key to decrypt it.  This chapter covers the basics of cryptology and its practical use.

**Objectives**
1. Review the fundamentals of cryptography;
2. Demonstrate usage of cryptography within information technology;
3. Understand cryptographic attacks and countermeasures.
## About Cryptology
Long ago, Julius Caesar commanded an army engaged in battle.  He and his generals would communicate with their geographically disbursed troops via messengers carrying battle plans.  The enemy understood this method of communication and would capture messengers and their battle plans to gain tactical advantage.  Caesar countered these interceptions by encrypting the battle plans, should they fall into the hands of the enemy.  Thus, encryption has its roots as a military tool that protected sensitive information from unauthorized parties. 

The field of **Cryptology** is the study of creating and breaking code systems that transform data to and from usable forms.  The design of these systems is called **cryptography** and consists of the development of mathematical processes that result in the encryption and decryption of information.  Cryptology also includes **cryptanalysis**, which attempts to undermine cryptographic efforts by breaking encryption and enabling unauthorized use.  Cryptologists often study and engage in both cryptology and cryptanalysis to develop secure or unbreakable encryption.
### Data Protection
A substantial portion of information security relies on encryption.  Those who are attempting to defend information at organizations will encrypt that data to protect it from unauthorized use.  The use of encryption is fundamentally a defensive position.  These security professionals and administrators ensure that sensitive information is stored and transmitted in a format unreadable by unauthorized third parties.  Some encryption is broken, some is good, while others are currently impervious to *cracking*.  Data defenders validate the grade and types of encryption being used in their systems by comparing them to current industry encryption standards.

Just as there are those who defend information, there are also attackers who seek to obtain that information.  Attackers will try to break the encryption that protects targeted data through cryptanalysis, which could reveal the information in a decrypted state.    

> [!info] Information - Blue and Red Team
> Individuals who defend information systems are called the *blue team*, while those attacking these systems are known as the *red team*.  Red teams and their members are not malicious actors and typically work on the side of an organization.  They use their attacking skills and tools to identify vulnerabilities with information systems and report findings to the organization, so the organization has a chance to fix security issues.  Blue team members work on the side of prevention, detection, and response at an organization.  They would be able to detect attacks and respond accordingly.  Sometimes these teams work independently from one another.  It is known as *purple team* when they work together and can be beneficial to both groups to identify issues efficiently and quickly.
### Encryption Goals
Encryption solves several information security issues.  It provides **privacy** by obfuscating data from unauthorized viewers.  Users of encryption can expect that their encrypted information is not readable by third parties.  Encryption also provides **authentication** assurances since authorized users with the shared key can participate in transferring of protected data.  Encryption ensures data **integrity** because encrypted messages that have been altered will fail decryption checks.  If encrypted data is altered before decryption, the algorithms used will not be able to validate it due to the modifications.  Finally, encryption can provide **nonrepudiation** by ensuring a sender of data cannot deny having sent it.  A convenient way to remember these features of encryption is through the acronym *PAIN*: (P)rivacy, (A)uthentication, (I)ntegrity, and (N)onrepudiation.
### Applied Encryption
Most people use encryption every day and do not even realize it.  This is because secure information systems have encryption seamlessly built-in and running in the background.  For instance, portable devices like laptops may have their storage media encrypted using Window's BitLocker or MacOS's FileVault.  These volume encryption technologies transform all data written onto the storage media into unreadable content that can only be accessed if the correct secret, or password, is applied.  The user of an encrypted laptop decrypts its contents by entering their logon password! 

Another common scenario where encryption is used is when browsing websites on the internet.  As of January 2024, approximately 85% of internet websites use encryption by default. [^1]  Web technologies use *transport layer security (TLS)*, commonly referred to by its now insecure predecessor *secure socket layer (SSL)*, that encrypts *HyperText Transfer Protocol (HTTP)* data payloads for requests and responses between web servers and client browsers.  The selection and use of TLS websites, also known as HTTPS in which the "S" stands for secure, is automatically established by the browser and web server without the average user even noticing.  Sometimes this HTTPS encryption has an error or misconfiguration, and the browser will display a danger warning notifying the user that any data processed between the website and their browser could be exposed.

Email systems use encryption seamlessly as well, at least in part.  Usually, an email client will establish an encrypted connection to their email server via HTTPS or *simple mail transport protocol secure (SMTPS)*.  The email server that processes and sends the client email does so over SMTPS ensuring the email is not readable to any intermediaries while it traverses the internet.  Then, the email's target audience uses their email client, such as Outlook or Gmail, to securely download the message and its contents, again over HTTPS or SMTPS.  This works well enough for security and is seamless to the email sender and receiver.  However, the email contents are in a decrypted state while in the email servers and anyone with access to those servers can view the unencrypted email.  A less seamless email encryption method is to encrypt the contents of the email before encrypting it with the email server.  Two popular client-side content encryption technologies are *Secure/Multipurpose Internet Mail Extensions (S/MIME)* and *pretty good privacy (PGP)*.  These technologies allow more advanced users to ensure that not even email administrators can view the contents of messages.

> [!note] Note - When to Encrypt?
> Encryption does more than protect data, it also provides a medium of trust between two parties through authentication and integrity (remember PAIN?).  It is important to use encryption technologies whenever you rely on information from third parties or when you want to protect data.  But where is the data that needs to be encrypted?  Data must be *encrypted at rest*, such as when persisted on storage media like a hard drive.  It also must be *encrypted in transit* while being transmitted over networks through Ethernet or Wi-Fi signals.  Finally, it should be *encrypted in use*, particularly when the data is in a computer's memory or RAM.
### Terms
There are several definitions to know when discussing encryption methods, technologies, and processes.  We have already covered several key terms and will use even more throughout this chapter.  The following terms will set up the base terminology when discussing how encryption works.

- **Plaintext** - the original message or content before being encrypted
- **Ciphertext** - the message or content that is encrypted from an output of a cryptographic function
- **Encryption** - to transform plaintext into ciphertext
- **Decryption** - to transform ciphertext back to plaintext
- **Algorithm** - also known as a *cipher*, is a logical or mathematic process that mutates data into a predictable format using a secret or key
- **Key** - a secret value used in a cryptographic algorithm to encrypt or decrypt data
- **Cipher Mode** - method of a cryptographic algorithm that determines how much data to process at a time

These terms will be used in this chapter and are common vernacular when discussing properties of encryption with security professionals.  Understanding these terms is crucial, because their properties help to identify the quality of encryption technology being considered for use. 
## Encoding
It is important to clarify that **encoding** is different from encryption.  However, it is important to review ciphertext as it is often not in a format that is readable or can be rendered by a computer's terminal or software.  Ciphertext in its raw form will display in a text processor, such as Notepad or within a terminal, as unusual Unicode characters or as blank spaces, because many of the bits do not have a corresponding character representation.  Software interacting with the system's kernel or the network stack needs to send and receive ciphertext but usually cannot process it in its ciphertext form due to the non-renderable bits.  The solution is to encode the raw ciphertext into a format of characters that can be used or transmitted by other systems.  Encoding has many other applications beyond the scope of encryption.

The *American Standard Code for Information Interchange (ASCII)* encoding format has 128 unique characters with which you are likely familiar.  The following table lists the character (Char), decimal and hexadecimal formats.  

![[../images/02/ascii.png|ASCII Table of Characters (source Wikimedia Commons)]]

The *decimal* format is a base 10, numbers 0-9, representation and each character is displayed by a numeric value.  Similarly, the *hexadecimal* format is base 16, 0-9 and A-F, totaling 16 characters, where a combination of 16 characters can represent all characters.  Using the above table, the character "$" shows as the decimal value 36 and the hexadecimal value 24.  There are many other encoding schemes that use the base method for encoding data.  Another very common encoding scheme is *base 64*, in which 64 characters are used in chunks of four and padded with the equal sign "=".  Base 64 characters include 0-9, a-z, A-Z, and special characters "/", "=" and "+".  Base 64 encoding is commonly used in HTTP because it does not include HTTP special characters like "?" and "&" that have explicit meaning in the HTTP protocol.  It is ideal for transmitting data without causing errors in the HTTP protocol, unlike other encoding schemes that may use characters interpreted by HTTP.

Data is also organized into chunks of bits consisting of ones and zeroes.  An 8-bit chunk can represent 2^8 or 256 unique combinations within the *Unicode Transformation Format 8 bit (UTF-8)* encoding system.  For example, the UTF-8 bit *binary* value `00100100` represents the dollar sign character "$".  The UTF standard goes beyond 8 bits and supports non-English language characters and other special characters like emojis.  

Each encoding type has a recognizable pattern which you should memorize to quickly determine the types of encoding used on blobs of data.  Having the skillset to observe a block of data and immediately see the type of encoding it uses will help you in your cyber analysis efforts.  The following table lists their type, hallmarks, and the encoding of "Hello World!" in various schemes we have covered.

| Type        | Hallmarks                                                                | Example                                                                                                     |
| ----------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| Binary      | ones and zeros                                                           | 01001000 01100101 01101100 01101100 01101111 00100000 01010111 01101111 01110010 01101100 01100100 00100001 |
| Decimal     | numbers only                                                             | 72 101 108 108 111 32 87 111 114 108 100 33                                                                 |
| Hexadecimal | numbers and letters a-f                                                  | 48 65 6c 6c 6f 20 57 6f 72 6c 64 21                                                                         |
| Base64      | numbers, upper and lowercase letters, and special characters +, /, and = | SGVsbG8gV29ybGQh                                                                                            |


> [!activity] Activity 2.1 - CyberChef
> CyberChef, https://gchq.github.io/CyberChef/, is the encoding and encrypting Swiss army knife of the internet and is available as an online web application or a command line interface (CLI) tool.  It enables users to transform values quickly and dynamically and to support several dozen encoding and encryption schemes with multiple configurations.  The left most pane, *Operations*, has a list of formats that can be dragged into the middle pane, *Recipe*.  The input value is entered into the upper right pane, *Input* and the output value is displayed on the bottom right pane, *Output*.  You can use multiple layers of formats to produce the final output.  The left pane options are written in the context as "to" or "from".  The logic used starts with the input value and is converted "to" or "from".  The following screenshot shows CyberChef in action by encoding "Hello World!" to hexadecimal format.
> ![[../images/02/cyberchef_activity.png|CyberChef Hello World Example]]
> 

Understanding encoding has many practical uses.  For instance, while performing a bitwise operation, one researcher recently discovered how to find the AWS account number from an AWS Access Key ID by removing metadata, decoding the ID using base 32, then decoding the hex values to ASCII. [^2]
## Ciphers
Let's apply some of the terms we have learned in this chapter.  There are two categories of encryption algorithms distinguished by how they handle the plaintext data being encrypted.  **Block ciphers** encrypt the plaintext in fixed-sized blocks of data, while **stream ciphers** encrypt continuously bit by bit.  

A common block cipher starts with an *initialization vector (IV)*, which is a random value that is used to XOR the first block of data.  An encryption *key* and the initial block are passed to the cipher which outputs ciphertext.  Each encrypted block is used as the IV of the next block until all blocks are encrypted.  The block size varies depending on the cipher being used but is usually between 64 and 128 bits.  The following diagram demonstrates the mechanics of a basic block cipher, *cipher block chaining (CBC)*, starting on the left and working towards the right.

![[../images/02/block_cipher.png|Block Cipher Diagram|500]]

The stream cipher uses a key and a *use only once (nonce)* value to create a key stream that is XOR'd with the plaintext input to produce the ciphertext.  This process is performed continuously bit by bit until the entire data stream has been processed.  The diagram below attempts to illustrate the process of a general stream cipher.

![[../images/02/stream_cipher.png|Stream Cipher Diagram|400]]

Both cipher types are also used to support decrypting ciphertext into plaintext by using a similar algorithm and the same key that produced the ciphertext.  In the decryption operation of the algorithm, the ciphertext and key are used as the input and the output of the algorithm is the original plaintext. 
## Cipher Modes
Block ciphers have various *modes* that have attributes that define how encryption is applied, such as by informing the size of blocks.  These modes of operation are algorithms that the cipher uses to encrypt data.  They detail how the cipher encrypts or decrypts each block, such as by using an initialization vector (IV) in CBC described earlier in the chapter.  Cipher modes differ in block size, how they are padded (blocks that do not meet the size are filled with the pad), and how they encrypt each block of data.  The following modes are some of the most common, but there are several other modes that are not being covered in this chapter.  You may be tempted to always select the most secure mode; however, there are tradeoffs such as speed, between each mode type that may need to be considered.  

The **Electronic Code Book (ECB)** mode is an older mode that was previously widely used until certain flaws became apparent by the cryptology community.  As one of the simpler modes, ECB takes each block and encrypts them separately using a key while working fast and consuming less resources than other cipher modes.  However, it is not recommended to use it any longer.

> [!warning] Warning - ECB Insecurity
> Because each block is encrypted individually using the same key, it lacks diffusion, and patterns emerge in the ciphertext that could enable cryptanalysis and decipher parts or all of an encrypted file.  The most famous visual example of this is the encryption of the Linux Penguin using ECB. [^3]  The image on the left is the unencrypted version of the file.  The middle image is encrypted using ECB and the last image is encrypted using a modern encryption mode.  Can you spot the issue with using ECB?
> ![[../images/02/ecb_encryption.png|Linux Penguin Encrypted using ECB (source Wikipedia)]]
> Obviously, the middle image encrypted using ECB is easily discernable and good encryption should result in the data being unrecognizable.  Remember this image the next time you are tempted to use ECB to encrypt data and avoid using an insecure cipher mode!

Another older cipher mode, **Cipher Block Chaining (CBC)**, is very popular and commonly found in use by information systems.  It is secure enough and encrypts blocks of data using an initialization vector and XOR'ing (inversing) the encrypted blocks to be used to encrypt the next block.  The block cipher diagram referenced in the Cipher section of this chapter is an example of how this algorithm operates.  Modern information systems using block ciphers should choose the **Galois/Counter Mode (GCM)** operation as it currently provides the most security.  It encrypts each block with a counter, or IV, then XORs the block.  GCM offers all the features of modern cryptography, including integrity and authentication computed via Galios field multiplication.
## Key Space
A cryptographic system relies on the encryption key remaining a secret as the other components used, such as the cipher, are assumed to be known by anyone.  To keep encrypted data secure, it is important to use a strong key value.  An encryption key is ideally long and random, also known as *high entropy*, to prevent certain types of attacks that could guess the key value.  Having a random key is vital because if the generated key followed an identifiable pattern, it would narrow the possible number of keys and be easier to crack.  Another heuristic of a strong key is its length.  The longer the key value is, the exponentially longer it would take to guess.  Secure keys are long and random!   Most security professionals accept a minimum key length of 128 bits (16 bytes); however, stronger key lengths are up to 512 bits (64 bytes).

> [!activity] Activity 2.2 - Key Space
> Let's examine generating a key using OpenSSL which comes preinstalled on the Ubuntu Linux VM.  OpenSSL is a widely used utility that includes every encryption function imaginable.  After launching the Ubuntu VM and opening a terminal, I enter the following command that generates a random 32-byte key.
> ![[../images/02/activity_key_raw.png|Raw 32-Byte Key|600]]
> This key could be used for encrypting data.  We can see that the output of the command consists of several non-ASCII characters.  Running the same command again, but this time piping it to `wc`, demonstrates that the output is comprised of 32 bytes, as shown in the 3rd column in the following screenshot.
> ![[../images/02/activity_key_wc.png|Byte Count of Key|600]]
> Encoding the key into base 64 format would make it easier to copy/paste and transfer between systems.  We could pipe the results of the first command to the `base64` utility or use the `-base64` option in OpenSSL to accomplish this.
> ![[../images/02/activity_key_base64.png|Base 64 the Key|600]]

Most encryption technologies can produce a secure key using a seed value that often consists of pseudo-random data from the system, time, and other factors.  A short key could be quickly guessed by checking every variation of bits in the length of the key.  Raw key values are stored as bytes, which are mostly not UTF/ASCII characters, as we learned in this chapter's encoding section.  Because keys need to be used as inputs, most encryption technologies expect the value of the key to follow a specific format.  This format begins with a header, continues with a base 64 encoded blob of the raw key value, and ends with a footer.
## Key Protocols
The process of encrypting data and accessing it with a key that you possess is an easy enough use case to understand.  The key, referred to as a *secret key* or *shared key* because it must be kept a secret, is used to encrypt data.  It is also the same key that can decrypt the data.  A key and algorithm that is used to both encrypt and decrypt data known as **symmetric encryption**.  The most common symmetric encryption algorithms are the deprecated *data encryption standard (DES)* and the modern *advanced encryption standard (AES)*.  However, things get more complicated if you want to share encrypted data between two entities that do not have a predetermined relationship.   

Establishing encryption between a website and each individual website user is a common example of this issue.  The party encrypting the data with a key can send it to the receiving party securely.  How does that party decrypt the message without the key?  They would need to also have the key generated by the sending party, but how do they get that key securely?  It would be unwise to send the key in a separate message that was unencrypted.  The sending party should encrypt the key before sending it, but what key do they use to encrypt the key?  Sometimes this effort is easy enough to overcome if within a trusted network or when the sender and receiver are working out of the same system.  The following graphic demonstrates the transfer of encrypted data over the internet using the same secret key (black keys) held by two parties (universally known as Bob and Alice).

![[../images/02/symmetric_keys.png|Symmetric Key Encryption|300]]


> [!activity] Activity 2.3 - Symmetric Encryption
> I'll continue the use of OpenSSL on the Ubuntu VM to demonstrate how to encrypt and decrypt a file using symmetric encryption.  First, I open a terminal and create a plaintext file with some data.  
> ![[../images/02/activity_symmetric_plaintext.png|Creating Plaintext File|600]]
> Next, I encrypt the plaintext file using AES256 code block cipher encryption from the OpenSSL utility.  I select the `-p` flag so the IV and Key will be displayed once the command completes.  Upon entering the command, I am prompted for a password that will be used to protect the encryption key.
> ![[../images/02/activity_symmetric_encrypt.png|Encrypting the Plaintext File|600]]
> Let's see what the encrypted output file contains using the `cat` command.
> ![[../images/02/activity_symmetric_cat.png|Ciphertext Result|600]]
> The original message has been encrypted!  Next, I use OpenSSL and the password to decrypt the `plain.txt.enc` file back to plaintext.  The `-d` option defines the decrypt mode and the `-A` option base 64 encodes the input file.
> ![[../images/02/activity_symmetric_decrypt.png|Decrypting the File|600]]

Sharing a symmetric key with a handful of users is manageable; however, a major issue arises when you want to share encrypted data with anonymous users at scale.  A common example of this problem is best illustrated by a website.  The website does not know who is requesting files from the webserver but there is a need to have the request and response payloads encrypted while traversing the internet.  Another conceptual problem arises when we realize we would not want to use the same encryption key for each anonymous user; otherwise, any anonymous user would be able to decrypt requests and responses for any user.  So, we need a solution that allows for the secure transfer of unique encryption keys between parties.   

**Asymmetric encryption** solves the scaling and sharing of keys by using two encryption keys derived from the same mathematical function of prime numbers.  The product of these large prime numbers, popularized by *Ron Rivest, Adi Shamir, and Leonard Adleman (RSA)*, is currently too difficult to factor and provides the basis for asymmetric encryption.  The *private key* is one of the keys generated as part of asymmetric encryption.  It is long and meant to be a secret.  The second key is shared with everyone and known as the *public key*.  The public key is not a secret and is offered in plaintext to anonymous users.  The public key is used for encrypting messages while the private key is used for decrypting messages. 

A user of a website requests the webserver's public key and creates their own symmetric key - typically done automatically by the user's browser.  Using the webserver's public key, the user's browser encrypts their symmetric key before sending it to the receiving webserver.  The webserver receives the user's encrypted symmetric key and then decrypts it using the webserver's private key.  All future communications between the client and server then use the user's symmetric key to encrypt and decrypt messages between each other.  The following graphic shows two parties using asymmetric encryption in which a public key (white key) is provided to the requestor and is used to encrypt keys for messages between the two parties.

![[../images/02/aysmmetric_keys.png|Asymmetric Key Encryption|350]]

To recap, symmetric encryption uses one secret key while asymmetric encryption uses a public and private key pair to encrypt a symmetric key.  Both key algorithms have their advantages over the other.  Symmetric is extremely fast, while asymmetric is significantly slower because there are several more steps and network latencies.  However, asymmetric encryption solves the key sharing and scaling problems of symmetric encryption.

>[!activity] Activity 2.4 - Asymmetric Encryption
>We can use OpenSSL on Ubuntu to encrypt messages using asymmetric encryption too!  After creating a public and private key pair using OpenSSL, a message can be encrypted using the public key and then decrypted using the private key.
>
>I create a 1024-bit private key into a file named `private.pem` and display the result.  Notice the key's header and footer and that the content is encoded in base 64.
>![[../images/02/asymmetric_activity_private_key.png|Private Key Generation]]
>Next, I create a public key into a file named `public.pem` that pairs with the private key.  This public key will be used to encrypt messages.
>![[../images/02/asymmetric_activity_public_key.png|Public Key Generation]]
>With the key pair generated, I create a message in a file called `plain.txt` and encrypt it using the public key, which is available in a new file named `plain.txt.enc`.  The contents of `plain.txt.enc` are not legible!
>![[../images/02/asymmetric_activity_encrypt.png|Asymmetric Message Encryption]]
>Finally, we can use the `private.pem` key to decrypt the message and display its content "hello world"!
>![[../images/02/asymmetric_activity_decrypt.png|Asymmetric Message Decryption]]
## Hash Algorithms
So called *one-way functions*, a **hash algorithm** takes an input and generates a cryptographic output value.  This fixed character length value will consistently produce the same value given the same input.  Good hash algorithms will create a vastly different hash output, or *digest*, with even the smallest change to the given input.  Speed is also an indication of a good hash algorithm as it makes it more practical to use.  Unlike typical encryption, hash algorithms are irreversible and do not have a mathematical way to turn the hash value back into plaintext value - there is no way to "unscramble the egg."  The diagram below demonstrates the general process of inputting a message into a hash function and yielding a hash value as an output.

![[../images/02/hash_function.png|Hash Use Process|500]]

Hash values provide a method to ensure integrity of a file or message.  If the user knows the original hash value of a file or message, they can generate another hash on a received message to verify it matches the original version.  Hash algorithms are also helpful when creating authentication systems, as they provide a means to avoid storing passwords in plaintext.  If a password is stored encrypted, or in plaintext, it runs the risk of one day being compromised and readily available for attackers to use.  Modern authentication systems do not store passwords in favor of storing a hash value of the password.  When a user logs into that system, the entered password is passed through a hash algorithm and the hash value is compared to the hashed value stored in the database.  If the two values match, then the user can be authenticated.

Not all hash algorithms have equal security value.  Some hash algorithms have been proven to be susceptible to *collisions*, where more than one input can create the same hash value.  Such algorithms should be avoided if concerned about security.  While hash values, or hashes, cannot be returned to their original values, there are techniques where the original input can be discovered.  This is accomplished by passing a lengthy list of potential values through the hash algorithm and comparing them to a subject hash value.  If there is a match with a value on that list, it is the implied original value.  As you can imagine, it takes many guesses to *crack* a hash value.  We will explore tools and experiment with hash cracking in later chapters. 

There are many cryptographic hash algorithms available for use.  While we will not cover all of them, we will review a few of the more popular or common ones.  The **MD5 message-digest algorithm** produces a 32 character, 128-bit, hash value.  It is amazingly fast and has been used since the early 90's.   However, in 2010 it was proven to be vulnerable to collisions and therefore should not be used for critical security operations.  Another immensely popular group of hash algorithms is the **secure hashing algorithm (SHA)** family.  The commonly used SHA-1 has 40 characters, 160 bits, and was discovered to be susceptible to collisions in 2017 by Google researchers.  It is common to still find SHA-1 being used within information systems, but its use should be avoided in favor of the SHA-2 version.  This version supports multiple bit length options 224, 256, 384, or 512.  The larger the bit length the more secure but also requires more time to compute the value.  The current recommendation is to use SHA-256 or SHA-512 for secure operations.

>[!activity] Activity 2.5 - Digest Verification
>Let's demonstrate the use of MD5 hash to prove the integrity of a message.  Using an Ubuntu VM, I open the terminal and echo a message into a file named `message.txt`.
>![[../images/02/activity_01_message.png|Create Message]]
>We can use the md5sum utility to determine the MD5 hash digest of a message.  The command outputs a 32-character value.  We could re-run this message on any computer and get the exact same result.
>![[../images/02/activity_01_hash.png|MD5 Hash of Message.txt]]
>Now, I replace the `message.txt` file with a slightly different message and recalculate the digest.  Notice the value is materially different from the original!
>![[../images/02/activity_01_rehash.png|Change Message and Rehash]]
## Encryption Authentication
Encryption can be used to authenticate a sender or receiver of data, even data that is in plaintext!  Such cryptographic authentication methods also have the added benefit of ensuring the integrity of the data.  In the following section, we will explore how a receiver of a message can authenticate the sender through *message authentication code (MAC)* symmetric keys.  Similarly, this same task can be accomplished using asymmetric keys via a *digital signature*.  Both methods leave the message in plaintext, so it does not provide confidentiality or privacy attributes.
### Message Authentication Code
A bidirectional conversation between two parties can use **Message Authentication Code (MAC)**, sometimes referred to as *authentication tag* or *keyed hash*, to ensure the integrity and authenticity of one another.  MAC provides assurance that the sender and receiver were the creators of the sent messages, as they both share a secret key combined with a message that is hashed to validate authenticity of communications.  If the message is altered in any way, even by one bit, the hash digest will not match, and the respective party will know that the message had been altered.  The MAC is a short piece of information that is constructed from a hash function, such as *hash-based message authentication code (HMAC)* or block ciphers like *Galois/Counter Mode (GCM)*, and sent along with the plaintext message as a file.  To demonstrate this, the following diagram shows a sender creating a MAC with a secret key and sending the message and MAC to a receiver that also has the secret key.  The Receiver uses the secret key to inspect the attached MAC, confirm the message's integrity, and authenticate the sender.

![[../images/02/mac_diagram.png|MAC Sending and Receiving|600]]

### Digital Signatures
A **Digital Signature (DS)** can be used when the need arises to verify a message with parties that do not have a shared private key.  Like MACs, DSs also provide authentication, integrity, and nonrepudiation benefits between the parties.  The DS has the advantage of sending the message along with a public key so that any receiver of the message can use the public key to verify the message and sender.  However, this use case only allows for the validation by a single direction of communication from the sender to the receiver and is limited by the receiver's ability to respond with a DS in kind.  DS can be *attached* or *detached*, meaning they can be embedded as part of the message (attached) or the signature can be its own separate file (detached).  In this diagram, the sender (on the right), creates a digital signature using a private key and sends the DS with a corresponding public key to the receiver (on the left).  The receiver uses the public key attached to the message to verify the signature.

![[../images/02/ds_diagram.png|Digital Signature Sending and Receiving|600]]


> [!activity] Activity 2.6 - Detached Digital Signature
> Let's demonstrate a detached digital signature.  I will use the `gpg` command preinstalled on the Ubuntu VM to generate a key.  Each key stored on the system's key ring requires a name, email address, and password.
> ![[../images/02/lab_ds_gen_key.png|GPG Key Generation]]
> Next, I create some content and store it in a file called `message.txt`.  This is the message that I will use to create a digital signature using the key I just created.
> ![[../images/02/lab_ds_message.png|Create Message to Sign]]
> Using `gpg` again, I create a detached signature in an output file called `message.txt.sig`.   This signature file would typically be sent along with the message so the recipient can verify the message's authenticity and integrity. 
> ![[../images/02/lab_ds_signature.png|Detached DS Creation]]
> The `gpg` utility with the `--verify` option checks that a signature corresponds with a message as demonstrated in the following command.  If the message were altered in any way, the verify check would fail with a "Bad signature" message.
> ![[../images/02/lab_ds_verify.png|GPG Verify DS and Message]]
## Steganography
Many centuries ago, a Greek historian wrote about a technique previously used to inconspicuously send a secret message.  A message was tattooed onto the messenger's shaved head and then their hair was allowed to grow back, concealing the tattooed message.  When the messenger arrived at their destination, their head was shaved and the message read.  The technique of hiding in plain sight to avoid detection is known as **steganography**.  A message can be smuggled in various media, including audio and image files.  

The most common steganography method is called *least significant bit (LSB)* in which an image file hides bytes of data by modifying the last bit of a series of bytes (8 bits).  For example, the byte `01101010` would have its last bit changed to accommodate a small part of the hidden message.  Changing the LSB this way only changes the color of a pixel by an imperceptible amount.  The entire message is laced through the image this way and can then be reconstructed by anyone with the knowledge that it exists!  For a steganographic image, there is no perceived difference to the image leaving the altered image visually identical to the original - thus hiding the message in plain sight.

>[!activity] Activity 2.7 - Steghide
>We can install Steghide in our Ubuntu machine and use it to hide a message in a JPEG file.  Before installing Steghide, I must add my user account to the sudo group and then reboot (or logout and log back in).
>![[../images/02/activity_steg_usermod.png|Adding User to Sudo Group|600]]
>After rebooting and logging back into the system, I run the update command and install Steghide.
>![[../images/02/activity_stego_install.png|Installing Steghide|600]]
>Using Google I download a JPEG named `image.jpeg` that will be used to hide my message.
>![[../images/02/activity_stego_download.png|Downloading JPEG|300]]
>Once the image is downloaded, I create a secret message into a file called `secret.txt`.
>![[../images/02/activity_stego_message.png|Create Message|600]]
>Now I can use Steghide to hide the `secret.txt` file in the `image.jpeg`.  Steghide uses the `-ef` "embed file" option for the message to be hidden and the `-cf` "cover file" option for the image file.  Running Steghide with the embed command prompts me for a passphrase which will encrypt the secret before embedding it within the cat image file.
>![[../images/02/activity_stego_embed.png|Embedding Secret Into JPEG|600]]
>The JPEG looks the same even though it now has the secret message embedded in it!
>![[../images/02/activity_stego_eog.png|Verifying Image Quality|600]]
>The image with the embedded message is ready to be inconspicuously sent to the receiver where the original secret message can be extracted.  To simulate this, I delete the original `secret.txt` file and then use Steghide's extract command with the `-sf` "stego file" option to retrieve the message. 
>![[../images/02/activity_stego_extract.png|Extracting Hidden Message|600]]
## Cryptanalysis
Cryptography is the practice of designing solutions to secure data, however, **cryptanalysis** is the practice of defeating cryptographic systems.  While it is tempting to associate cryptanalysis with negative connotations, as though trying to break an encryption system is immoral or illegal, it is in fact beneficial to security.  A common theme throughout information security is to test the capability of security systems to continuously improve them; otherwise, malicious actors may identify vulnerabilities and attacks unknown to defenders.  Cryptanalysts have developed many crypto attack methodologies that include attacking the data, the cryptography, and the systems that implement them.  Let's briefly explore some of the more popular attack vectors. 

In a **known-plaintext attack**, the actor has a copy of both the plaintext and the ciphertext.  Their goal is to derive the encryption key using the cipher which is assumed known.  If the attacker can determine the key used, they could use it to decrypt ciphertext and retrieve the plaintext.  The following diagram illustrates this type of attack.  From this example, you can observe that the plaintext has two consecutive "l"s in the third and fourth position whereas the ciphertext has two consecutive "m"s in the same relative position.  This pattern enables the attacker to determine that a shift cipher was used with a key of 1.  A basic shift cipher moves the letters of the alphabet by the key value, in this case an "a" becomes a "b".  To decrypt the ciphertext, we simply shift the letters in the opposite direction by the key value 1.  The first letter of the ciphertext "i" becomes an "h".  Repeating the process for every character reveals the original plaintext!

![[../images/02/attack_known_plaintext.png|Known-Plaintext Attack|400]]

The **chosen-plaintext attack** requires the actor to apply a plaintext of their choosing to encrypt.  It assumes the key is unknown, but the attacker has indirect access to it as they can encrypt messages with it.  They observe the system's output based on their input and try to derive the key.  They can repeat this as many times as needed to understand how the cipher works and derive the key being used.  Once the key used has been identified, the attacker can decrypt any accessible ciphertext.  As illustrated in the following diagram, the actor chooses the plaintext entering into the cipher and can observe the output.

![[../images/02/attack_chosen_plaintext.png|Chosen-Plaintext Attack|350]]

A much more difficult data attack is the **ciphertext-only attack** where the actor only possesses the ciphertext and does not have the availability of any plaintext to compare or test through the cryptographic system.  The following diagram illustrates what the actor has available to them in this attack type to derive the encryption key, which is not much!  There are still several techniques that can still be used to try to crack this encryption, even with such limited information.

![[../images/02/attack_ciphertext_only.png|Ciphertext-Only Attack|150]]

An example of a ciphertext-only attack technique that is particularly effective against shifting cryptographic systems is a **differential attack**, or **frequency cryptanalysis**.  In this attack, the actor needs a lot of ciphertext and analyzes the frequency of each character.  For example, they will count how many times the letter "a" appears in the ciphertext.  They then compare these collected character frequencies to a similar analysis of a standard language like English.  Consider that the letter "z" is less commonly used in English than the letter "a".  You would expect to find many more "a"s than "z"s in any given body of regular text.  While the frequency of letters in a shift cipher will not perfectly align with normal English language, it will reduce the number of permutations to determine which ciphertext letter corresponds to which plaintext letter.  Consider the following diagram from https://crypto.interactive-maths.com/frequency-analysis-breaking-the-code.html that depicts two bar charts with this analysis.  The most common ciphertext letter frequency on the right is the letter "s" while plaintext analysis shows that the most frequent letter is "e".  Perhaps every ciphertext letter "s" in this example is the plaintext "e"!

![[../images/02/attack_frequency.png|Frequency Analysis Charts (crypto.interactive-maths.com)|700]]

Systems implementing cryptographic solutions can also be attacked.  For example, an encryption key exchange over a network can be stolen by an actor through a **man in the middle (MiTM)** attack.  In this scenario, the actor has positioned themselves between the sender and receiver of a cryptographic key being sent over a network.  Having access to this traffic, the actor can observe the encryption key in plaintext and can use it to decrypt any ciphertext generated with the key.

![[../images/02/attack_mitm.png|Man in the Middle Attack|400]]

Another attack on cryptographic systems can be conducted adjacent to the technology being used in what is referred to as a **side-channel attack**.  This can take many forms, but one recently discovered method derives cryptographic keys by measuring the effects of voltage draw through the level of light emission of an LED displayed on the front of a computer that is performing cryptographic operations! [^4] 

Cryptographic hash algorithms can also be attacked, which if successful, can enable actors to compromise the integrity or authentication of a system.  The classic **brute-force attack** consists of applying every combination of characters through a hashing algorithm and then comparing the results to a known hash.  The original value used to create the target hash digest can be identified through a brute-forced value whose hash digest matches that of the original.  Consider the following diagram that illustrates this attack.  The list on the left represents every lowercase combination of four characters.  Each set is passed through the hash algorithm to produce a hash value.  These combination digest pairs are then used to cross reference a target hash value.  If the target hash matches a hash value on the list, the value used to produce that hash can be identified.

![[../images/02/attack_brute.png|Brute-Force Attack|550]]

Another hash algorithm attack takes advantage of hash collisions, previously discussed in this chapter, and is called a **birthday attack**.  It gets this interesting name from a statistical phenomenon known as the *birthday paradox*.  Unintuitively, a room with 50 people has a nearly 95% chance of two people sharing the same birthday.  Attackers can take advantage of collisions by producing a trusted digest that has been manipulated.  Take the given scenario of an executable download from the internet.  Normally a user can verify the download's validity by calculating the hash value and comparing it to a known good result.  But, as shown in the following diagram, a malicious actor that has access to the source of that file before a user downloaded it, can alter that executable with malicious code, which produces the identical hash value as the original.  The victim of this attack would expect the malicious version was authentic because the hash value matches, even though they have downloaded a malicious file with an identical hash!
![[../images/02/attack_birthday.png|Birthday Attack|450]]

## Exercises

>[!exercise] Exercise 2.1 - Encoding and Decoding
>Encoding and decoding values is very common when analyzing data and having the skillset benefits many security roles.
>#### Step 1
>Using the encoding patterns learned in this chapter, identify each strings' encoding:
>- `WW91IGhhY2tlciB5b3UhIQ==`
>- `69 110 99 111 100 105 110 103 32 105 115 32 110 111 116 32 101 110 99 114 121 112 116 105 111 110 32 58 41`
>- `77 30 30 74 20 77 30 30 74`
>- `48 65 78 20 69 73 20 63 6f 6d 6d 6f 6e 6c 79 20 75 73 65 64 20 77 69 74 68 20 61 73 73 65 6d 62 6c 79`
>- `01101111 01101110 01100101 00100111 01110011 00100000 01100001 01101110 01100100 00100000 01111010 01100101 01110010 01101111 00100111 01110011`
>#### Step 2
>Decode each string from step 1 using CyberChef https://gchq.github.io/CyberChef/.
>#### Step 3
>Using CyberChef, encode the following string into a base 32 format.
>`Cyber Chef is an awesome tool!`


> [!exercise] Exercise 2.2 - Key Space
> OpenSSL is a command line tool available in Linux systems that can perform almost any cryptographic activity you can imagine.  It comes preinstalled on Ubuntu and can be used to generate random encryption keys of a desired length.  Start your Ubuntu VM and open a terminal.  Create a random 32, 128, and 256 key using the following commands.
> ```bash
> openssl rand -base64 32
> openssl rand -base64 128
> openssl rand -base64 256
> ```


> [!exercise] Exercise 2.3 - Symmetric Encryption
> We'll continue the use of OpenSSL on your Ubuntu VM to complete this exercise in which you will encrypt and decrypt a message using symmetric encryption.
> #### Step 1
> Open a terminal and create a plaintext file with a secret message.  
> 
> `echo "some secret message" > plain.txt`
> #### Step 2
> With the plaintext file created, encrypt the message using AES 256 encryption code block cipher mode.  
> `openssl enc -aes-256-cbc -p -in plain.txt -out plain.txt.enc`
> 
> Review the encrypted message using the `cat` command and observe that it is unrecognizable from the original message.
> 
> `cat plain.txt.enc`
> 
> #### Step 3
> Next, decrypt the encrypted message using the key you set in step 1.
> 
> `openssl enc -aes-256-cbc -d -A -in plain.txt.enc`
> 
> If successful, you should have your original message displayed!
> ![[../images/02/symmetric_exercise.png|Symmetric Exercise Result]]


> [!exercise] Exercise 2.4 - Hash Generation
> In this task you will create hash digests using Ubuntu's native md5sum and sha256sum tools.
> #### Step 1
> Create a message in a new file to be used with hashing utilities.  Open your terminal on your Ubuntu machine and enter the following command.
> ```bash
> echo "Tamperproof Message: crypto is the coolest!" > message.txt
> ```
> #### Step 2
> For this step you will take the MD5 and SHA-256 values of the created file from the previous step.  Enter the following commands in the directory where `message.txt` resides.
> ```bash
> md5sum message.txt
> sha256sum message.txt
> ```
> Notice the difference in the digest length between MD5 and SHA-256.


> [!exercise] Exercise 2.5 - Detached Digital Signature
> Debian based Linux systems usually come pre-installed with GNU Privacy Guard (GPG) that offers the ability to create digital signatures (DS).  You will use your Ubuntu VM in this exercise to create a detached DS and to verify it.
> #### Step 1
> Acting as the sender of the message, we will create a key-pair using `gpg` via the following command.  Once the command is run, you are prompted to enter a name and email address.  You will also be asked to enter and verify a password for your key ring that is created.  Upon successful execution, a public key is created along with an entry in the system's key ring.
> ```bash
> gpg --gen-key
> ```
> #### Step 2
> Create a message to sign using the following command.
> ```bash
> echo "Message integrity and authentication are very cool" > message.txt
> ```
> #### Step 3
> With the key-pair and message created, you are ready to digitally sign it using GPG.  The following command will output a `message.txt.sig` as a detached separate file from the original `message.txt`.  Upon entering the first command, you will be prompted to enter your password to access the key ring.  The second command displays the contents of the signature - note it is a public key!
> ```bash
> gpg --output message.txt.sig --armor --detach-sig message.txt
> cat message.txt.sig
> ```
> #### Step 4
> The message and the signature are now ready to be sent.  You can pretend to send both files to another party.  When the receiver gets your message and detached signature, they will need to verify that the message has not been altered and that it was really you that sent it.  The receiver will use GPG with the verify option to confirm the message in the following command.  GPG will output a "Good signature" message upon successful validation.  Run the following command to verify the message.
> ```bash
> gpg --verify message.txt.sig message.txt
> ```
> #### Step 5
> Alter the `message.txt` content slightly and then re-run the GPG verify command and then answer the following questions:
> - What is the output of the validation?  
> - Are you notified that the signature is bad?  
> - Explain what this means to the receiver of a message with an unverified or bad signature.  
> - What are the implications?


> [!exercise] Exercise 2.6 - Steghide
> Let's use steganography to hide a secret message within a JPEG file using a tool called Steghide.  You will install the software, create a message and conceal it within an image file.  Afterwards, you will extract the secret from the image.  Start and login to your Kali VM to complete this exercise.
> #### Step 1
> From your Kali VM, open a terminal and update your system using the following command.
> ```bash
> sudo apt update -y
> ```
> Your user may not have sudo privileges and the update command might therefore fail.  If needed, switch to the root user and modify your normal user by adding it to the sudo group using the following commands.  Make sure to replace `USERNAME` with your account's name.  After running the commands, you will need to log out and log back in for the user modification change to take effect - I typically just reboot to accomplish this.
> ```bash
> su -
> usermod -aG sudo USERNAME
> ```
> With your system updated, install Steghide using the following command.
> ```bash
> sudo apt install steghide -y
> ```
> #### Step 2
> With Steghide installed on your system, you will need a secret message and a JPEG image.  First, create a message using the following command.
> ```bash
> echo "Launch Code: 31337" > secret.txt
> ```
> Next, open your VM's browser and navigate to [https://www.google.com/imghp?hl=en](https://www.google.com/imghp?hl=en) and search for an image.  Right-click the image and save it as a JPEG.  If the image cannot be saved as a JPEG, then you will need to select another image or try to convert it.  You might consider moving the downloaded image to the same folder where the secret.txt file was created.
> #### Step 3
> Now that the software is installed, a message was created, and you have downloaded a JPEG, you are ready to hide the message into the image.  With Steghide, you will use the embed command and options `-ef` (embed file) and `-cf` (cover file) to insert the secret message into the image.  The original image will be modified yet will look the exact same.  Make sure to replace the `IMAGE.JPG` with the image name and path of what you downloaded.  You will be prompted to supply a password after running the command - make sure you remember it!
> ```bash
> steghide embed -ef secret.txt -cf IMAGE.JPG
> ```
> Go ahead and check the image and compare it to the original.
> ```bash
> eog IMAGE.JPG
> ```
> Consider moving the steg file (image) to another folder or removing the original message as you will next demonstrate extracting the message.
> #### Step 4
> Pretend this stego-image was sent to another party that knew of the hidden message and has password.  They can use Steghide to extract the message and reveal its contents.  Run the following command that uses the `extract` command and `-sf` (steg file) option to extract the message.  Unless you have moved the steg file image or deleted the original message, when you extract the message, you will overwrite the original message that is in the folder.  Make sure to replace `STEG_IMAGE.JPG` with the name and path if not in the same folder as the current working directory.
> ```bash
> steghide extract -sf STEG_IMAGE.JPG
> ```
> Now check that the message was extracted and observe its contents.
> ```bash
> ls -la
> cat secret.txt
> ```

> [!exercise] Exercise 2.7 - Known Plaintext Attack
> Here is a puzzle for you to solve.  Applying what you have learned about known plaintext attacks, you will attempt to break my custom encryption by having only the plaintext and ciphertext.  Your goal is to break the encryption and describe the custom algorithm used based on only the following information:
> Plaintext: `Break my simple encryption`
> Ciphertext: `rOe nx zlzfvrcya rlpevcgba`



[^1]: Usage statistics of Default protocol https for websites; January 2024; https://w3techs.com/technologies/details/ce-httpsdefault#:~:text=These%20diagrams%20show%20the%20usage,85.1%25%20of%20all%20the%20websites.
[^2]: A short note on AWS KEY ID; by Tal Be'ery; October 24, 2023; https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489
[^3]: Block cipher mode of operation; Wikipedia; January 2024; https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
[^4]: Hackers can steal cryptographic keys by video-recording power LEDs 60 feet away; Dan Goodin; June 13, 2023; [Hackers can steal cryptographic keys by video-recording power LEDs 60 feet away | Ars Technica](https://arstechnica.com/information-technology/2023/06/hackers-can-steal-cryptographic-keys-by-video-recording-connected-power-leds-60-feet-away/)