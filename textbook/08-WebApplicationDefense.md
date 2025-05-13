<span class="chapter-banner">Chapter 8</span>
# Web Application Defense
![](../images/08/web_defense.jpg)

**Objectives**
1. Understand the basic architecture of web applications and supporting systems.
2. Harden web application servers with encryption and web application firewalls (WAF).
3. Describe the secure development of modern web applications.

The connections between networks over the past several decades have given rise to the internet.  However, the internet's popularity grew substantially in the late 90's due to the rise of the *hypertext transfer protocol (HTTP)* and website technologies.  Many people came to understand the internet as a collection of web pages; however, informed individuals know that the internet offers much more.  Early websites often only offered a static brochure of information with little interaction from users.  As popularity grew, so did the demand and expectation of dynamic features, which eventually carved the way to *web applications*.  These sites provide users with a rich experience comprised of dynamically generated pages and user inputs while at the same time increasing the security risks.  In this chapter, we will explore web application fundamentals and basic security architectures used with modern domains.  We will also learn how organizations ensure the secure development of web technologies in their *software development lifecycles (SDLC)*.
## Web Application Fundamentals
The first major section of this chapter will offer the reader a brief working overview of web architecture and design.  It will also cover some of the common development strategies and technologies in use by organizations.
### Web Architecture
You may recall covering the *client-server model* in earlier networking chapters within this textbook.  HTTP is a stateless protocol which means that the connection state does not persist after data transfer.  This means that, as part of the protocol itself, a client and server's interaction starts and ends with a request and a response.  The client is usually a web browser, such as Chrome or Firefox, and the server is a *web server* which has an HTTP service.  Common web server technologies for Linux systems are Apache and Nginx.  Microsoft Windows systems often use *Internet Information Services (IIS)* web servers.  These technologies are installed on base operating systems and configured to listen on network ports waiting for incoming requests.  HTTP is usually served over port 80, or 443 when using transport layer security (TLS).   As illustrated below, a request connection is initiated by the client.  The web server receives the request and provides the response.  Typically, the data retrieved from web servers are files, images, and data.

![[../images/08/client_webserver.png|Connections Between Clients and Web Servers|250]]

These servers can deliver *static* files including images, *hypertext markup language (HTML)* content, and *cascading style sheets (CSS)* used for centralized formatting.  The developers of static sites design the layout and flow of pages.  The next generation of web technologies created the *dynamic* generation of web pages.  Typically, the client provides the web server with some information as an input which it uses to generate a unique page for the client.  Examples of web technologies that create dynamic content include PHP, Java Server Pages (JSP), and Ruby on Rails.  Usually there is a database server that holds all the data and supports the functioning of the web site.  

As part of the web server's processing of client requests, it reaches out to the database server and *creates*, *reads*, *updates*, or *deletes* *(CRUD)* information that is used in the final file response to the client.  The database server, such as MySQL or Postgres, can be installed on the same server as the web server, but is best installed as a standalone server and not directly exposed to the internet.  Having these servers on different machines ensures *separation of concerns* and allows administrators to maintain components individually.  This separation also provides security value as it allows more granular access control as well as limits the blast radius of compromises.  The collection of the system server, web technology, database, and programming language are often referred to as the *technology or web stack*.

A downside to dynamically generated page architecture is that it requires heavy processing and rendering of pages by the web server.  A lot of server resources are wasted generating the same pages over and over again with only some data content differing between each generation.  It also requires that the single server maintain the frontend and backend logic of the application.  Instead of having a unique dynamically generated file for each page or file, some modern systems use a **single page application (SPA)** architecture in which a single frontend application is downloaded to the client.  The web server is then free of generating pages and instead handles the logic to generate data to send to the client.  The client receives the data and updates the SPA presented to the user.

![[../images/08/spa.png|Single Page Application Architecture|300]]

The SPA architecture illustrated above demonstrates how the frontend application is downloaded to the client (1 & 2).  The client then requests data from the web server (3) that uses the information stored in the database (4) to generate and deliver a response (5 & 6).  The data returned to the client is then injected into the frontend SPA originally requested by the client.  

You may have noticed some websites you visit load partially and after a second or two, then display the relevant data on the page.  This could be indicative of an SPA first downloading the application from a frontend web server and then retrieving data from the backend system.  As you navigate the site, the pages being rendered are actually performed locally in your browser; however, the data of the pages is being retrieved from the web server!  As mentioned earlier in this section, browsers can interpret HTML, CSS, and image files but the use of logic in those technologies is very limited.  JavaScript is used to interact with the browser's *document object model (DOM)*, which is the structured representation of a page, and to apply logical operations.  This language originally was developed for client browser use but has recently been popularized for backend programming as well through NodeJS.  Therefore, a frontend SPA is usually written in JavaScript while the backend can be written in many other programming languages,  such as JavaScript or languages mentioned earlier in the chapter.

Backend web application systems, sometimes referred to as *services or microservices*, are not designed as a user interface.  They are web-based **application programming interfaces (API)** meant for machine-to-machine interactions and not human to machine.  Each API URL, called *endpoints*, accepts one or more *HTTP methods* that could align with CRUD operations.  APIs respond with a blob of data that is organized in a manner which can be easily processed by the SPA.  Two popular formats for this data are the *extensible markup language (XML)* and *JavaScript object notation (JSON)*.

> [!info] HTTP Methods
> HTTP supports several request types called HTTP methods.  Common methods are PUT, GET, POST, DELETE which align with database CRUD operations.  When a client makes a request to a web server, it must include the HTTP method along with the target resource (e.g. file or API endpoint) and parameters.  The web server receives the request and parses the method, file path, and parameters which are used to prepare the response.

The following diagram builds off the basic client and web server model shared earlier in which an SPA client makes an HTTP request to an API endpoint on a web server.  The web server responds with a JSON object that includes key value pairs of data that is processed by the SPA to give the user a unique experience. 

![[../images/08/api.png|API Interaction with SPA|350]]

In this image, the data returned from the server is the name of the user and an empty response for the car variable.  The SPA parses this data and uses the name field to render the text "Welcome John!" and display the no car selected icon.  The delivery of this small JSON file is less resource intensive than the web server having to process and generate the entire page as with dynamically generated pages.
### Engineering Processes
Organizations with more than a handful of web developers will usually establish technologies and practices to facilitate the creation of web applications.  As web development teams expand, it becomes increasingly important to establish how software is created and delivered to ensure the consistency and functionality of the web application.  Additionally, these management systems assist in the later modification of the web application helping to ensure changes do not break the application's functionality for its userbase.

Many software development lifecycles (SDLC),  or general software development methodologies, have been created over the decades, and we will focus on two popular ones.  The SDLC *waterfall* is a method of planning and executing the workload of a software project.  It usually begins with a team determining the objectives, timelines, and documentation of the software needed.  These plans are then passed to a team of developers who are responsible for creating the software in accordance with the plan.  Once created, the software is tested and delivered as a final product, at which point it goes into a maintenance mode of making only the changes needed to ensure its continued functionality.  Waterfall is usually criticized for being rigid, unadaptable, and costly due to underestimates of timelines and costs.  A software project that takes two years to create may miss market opportunities and therefore deliver little business value.  

Many development shops now use the *agile methodology* of designing and delivering software.  Workload under agile management systems is created and added to a backlog of requests for development.  Agile teams then select and commit to work in 1-3 week *sprints* after which a new sprint or catalog of work is created and the process continues.  This method of development allows for the capitalization of changing market conditions; however, it is often criticized for not allowing enough investment into any one area long enough to produce the business value needed.  Check out the Manifesto for Agile Software Development (https://agilemanifesto.org/) for more information on this SDLC practice.

As an application grows in size and complexity, it becomes increasingly difficult to ensure the quality of the software.  Many tactics are used by developers to ensure the organization and quality of the source code, which may include *clean code strategies* and frameworks.  **Software testing** is the process of ensuring that the software created performs as expected.  Tests are written alongside the application and are used to continuously validate the functionality of the code being developed.  *Unit* test logic ensures that a specific function or method returns specific output given a set of inputs.  *Integration* testing measures the connections between systems, such as between a web server and a third-party API.  *Functional* testing follows along the user interface and checks that the flow of the application performs as intended.  Finally, there are *security* tests that check for vulnerabilities and misconfigurations which we will explore in the second half of this chapter.

> [!info] Monoliths Versus Microservices
> Some software is developed into one large and complex project called a *monolith*.  These systems require a high cognitive load and learning curve for developers to understand how the application functions.  Another concern with monoliths is that they may run on a single system and if that system malfunctions, the entire application could become unavailable - a single source of failure.  The *microservice* architecture breaks a monolith into interconnected yet independently run components.  Doing so allows each component to be run on separate systems from each other.

Developers need a method of sharing the source code with each other as well as administrators that deploy the code to web servers.  **Version control systems (VCS)**, such as Git, which is widely used on platforms like GitHub, are source code management systems that provide developers many features, including a central place to store and share code, ability to verify code before it is merged into the system, and audit functionality to review code changes over time.  These systems are of great security interest as many organizations place a high business value on the source code of their applications.  Source code could also contain vulnerabilities that are exposed in the running application.  In addition, VCS themselves can have misconfigurations or other vulnerabilities that could compromise the integrity of applications and the environments they run in.

Many development shops divide development work and the running of applications between two teams, known as development and operations.  The separation of these two entities provides an opportunity for control as the operators, who are usually system administrators, can ensure that developed software meets system requirements prior to being released to a production environment.  However, this division in responsibilities can lead to a moral hazard in which a developer may not care about the performance of their code, as the operating system it runs on is not their problem to handle.  Another criticism is that administrators may prevent the deployment of software as a gatekeeper without understanding the business demands or how the application works.  

Out of these problems, a newer process for operations emerged known as *DevOps*, which combines development and operations.  In its purest form, DevOps engineers are developers that are responsible for the deployment and maintenance of systems their applications run on.  Such a strategy requires the developer to understand both development, as well as system administration, which could be a steeper learning curve than most developers are willing or able to handle.  Many development shops instead have a separate development team and DevOps team that work closely together to deliver safe and stable software which balances the needs for most organizations.  In these shops, DevOps engineers are responsible for automation of *continuous integration/continuous delivery or deployment (CI/CD)*, *infrastructure as code (IaC)*, and site reliability.

It can be a challenge for a developer to deliver a developed application to a DevOps team for deployment, or even to share the application with other developers.  The developer will usually be focused on the application and not the prerequisite technologies or instrumentation needed to run the application.  To streamline this process, many teams make use of **container** technologies, which separate the running of applications in an isolated local environment that shares the host's operating system's kernel.  Containers offer the developer a method of transferring the needed system setup between their local environment to that of another developer all the way to a production environment.  Containers differ from virtual machines (VM), which run independent operating systems on hypervisors, in that they use the host's operating system kernel.  Containers are often mistaken as a security demarcation boundary; however, a container does not represent a security boundary and should not be expected to protect the host computer from attacks through the container.
## Web Application Defense
Armed with our basic understanding of web application architecture and engineering practices, we can begin to examine the security of web technology systems and secure development processes.  This section examines how to set up a web server with TLS encryption and a Web Application Firewall (WAF).  Then we review web application security risks and treatments alongside the practical application of security scanning tools.
### Encrypting HTTP
When a client establishes an HTTP connection with a web server, the communication between the two entities is in plaintext.  Any device sitting between the two entities, such as routers or MitM attackers, can inspect the traffic in its plain form.  This is a risk that is intolerable, as many web applications today accept and transmit sensitive information like online bank login credentials and credit card numbers.  The confidentiality of such information is one serious concern, but so is the integrity of the data.  It is just as likely that ensuring the integrity of the data is just as important to web users as keeping the data private.  For example, ensuring a bank transfer account number was not altered while in transit over HTTP would be very important to the person expecting to send or receive those funds.

The **Transport Layer Security (TLS)** protocol supports many networking technologies by providing cryptographic features to the protocol, including HTTP.  Usually, a protocol that uses TLS adds the letter "S" to the end of the protocol acronym, as is the case for HTTP where the encrypted version is called HTTPS.  This secured protocol is served over port 443 by default and is recognized by clients automatically.  It is easy to not notice when a website uses HTTPS, as it has become expected for any reputable website.  In order to use TLS with HTTP, a web server must be configured with a valid certificate.  Once configured, the system uses asymmetric encryption keys to security exchange a symmetric session key that is used to encrypt messages with clients, as demonstrated in the figure below.

![[../images/08/https.png|HTTPS Connection Flow|400]]

An HTTP client establishes a TCP connection with a web server over port 443 configured for TLS encryption.  The client and web server then negotiate the encryption ciphers and key strength they will use by selecting the most secure configuration compatible by both.  With RSA asymmetric encryption, the web server then delivers its **certificate**, which includes the information about the encryption it uses, such as key expiration, issuer, and the public key.  Having received the web server's public key, the client generates a unique, private symmetric key and encrypts it using the web server's public key.  The client then sends its encrypted symmetric key to the web server that uses it to encrypt responses to the client.  The client also uses the symmetric key it generated to encrypt any requests.

>[!information] Info - RSA versus ECDHE
>The key exchange described above illustrates the *Rivest-Shamir-Adleman (RSA)* protocol.  However, many modern TLS implementations may use the *Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)* key exchange which does not directly encrypt the exchanged symmetric key with the public key.  Using ECDHE, the client and server jointly derive a symmetric key through an ephemeral key exchange.

A TLS certificate can be generated using tools like OpenSSL that was demonstrated in the Cryptology chapter.  The issue is that web browsers will not recognize such certificates as they have been **self-signed** instead of being issued by a recognized and preconfigured **Certificate Authority (CA)**.  A *root CA* can generate certificates or can generate *intermediate CAs* that can also create certificates.  CAs can expire certificates earlier through *Certificate Revocation Lists (CRL)*, should a private key ever be compromised.  The following diagram illustrates a root server that stores the private keys needed to create certificate authorities with a *Common Name (CN)*.  The CA can then issue certificates with their own name, domain, expiration and public key.

![[../images/08/certificate_authorities.png|Certificate Authority Creation Flow|600]]

Protecting the root CA server that holds the private keys to create CAs and certificates is paramount.  Should the server ever be compromised, all of its trusted certificates would need to be invalidated, as the attacker could decrypt or modify any HTTPS traffic encrypted by them.  By default, all certificates generated by all CAs are not trusted by operating systems and browsers, and the use of any untrusted certificate will result in encryption error messages.  This may prevent access to the requested resource.  Therefore, all browsers and operating systems come pre-installed with dozens of already vetted and trusted CAs.  Administrators can add any CA to a browser or operating system, at which point the client will trust any certificate produced by that CA, assuming no misconfigurations or expirations.
### Web Application Firewall
We covered network and host firewalls in earlier chapters, but there is another firewall type often used with well protected web applications called a **Web Application Firewall (WAF)**.  These firewalls are used for inspecting HTTP traffic for malicious payloads and will alert or block traffic from reaching the web server.  WAF solutions, such as the opensource ModSecurity or the commercial Imperva, sit between the client and the web server and act as a proxy, called *TLS termination* or *TLS offloading*, relaying traffic to and from the involved entities.  This would ordinarily break TLS encryption, so the WAF solution must be configured with its own TLS certificates and perform decryption and encryption activities in order to inspect HTTPS data without causing TLS errors to be presented to the client.  WAF technologies are very helpful at preventing the exploitation of known or unknown vulnerabilities in a web application.  For example, if there is a known SQL injection vulnerability in an application which requires some lead time to fix, a WAF can block any related malicious traffic that attempts to abuse the SQL injection vulnerability while developers work to correct the vulnerability within source code.

>[!warning] Warning - Using WAFs Instead of Secure Code
>WAFs should never be used as a replacement for secure code.  It is tempting for business managers to over-rely on a WAF solutions instead of implementing secure code practices or investing in fixing legacy security vulnerabilities.  This is not recommended as with any control there are often ways to bypass them.  For example, most WAF solutions will not inspect the entire HTTP request; and an attacker could smuggle a malicious payload in a large request exploiting a vulnerability that was thought to be protected. 

When the WAF inspects the traffic, it runs the HTTP packets through a library of rules that have been developed to detect malicious patterns in the header and data sections of requests and responses.  Each WAF solution has its own syntax for creating rules, but all have some common characteristics such as a name or description of the rule, the action the rule should take like alert or block the packet, and a regular expression that will identify a malicious pattern.  Some rules are proprietary, however there are many opensource and free community supported rulesets that can be used.  The following image shows an example of a ModSecurity rule that will deny any HTTP requests that includes `/index.php` in its URI.

![[../images/08/waf_rule.png|WAF Rule Example|500]]

A ModSecurity rule syntax starts with the label "SecRule" that informs the WAF of the rule configuration.  The next block in the rule contains a variable from a preset list which sets the context for the rule.  In the example above, the variable `REQUEST_URI` will be used to set a rule on an incoming request's URI data.  The operators block includes the logic of the rule, such as by the use of regular expressions.  Finally, the actions block of the rule includes metadata, transformations or how the data should be preprocessed before applying the rule logic, and the action the rule should take, such as logging or blocking.

>[!activity] Activity 8.1 - Web Server Security
>Usually system administrators, or DevOps engineers, set up the TLS encryption and WAF services protecting web applications.  In this activity, I will demonstrate installing Apache web server configured to use a self-signed certificate.  I will also install ModSecurity WAF and test its functionality by attempting a cross-site scripting (XSS) payload.
>
>The Ubuntu VM will be used in this demonstration in Bridge Adapter network mode.  Once booted up and logged in, I open a terminal and switch to the root user on the root directory.
>```bash
>su -
>cd /
>```
>![[../images/08/server_activity_root.png|Switch to Root User and Directory|600]]
>Because I will be installing software, I run an update on the system before attempting any software installations.
>```bash
>apt update -y
>```
>![[../images/08/server_activity_update.png|System Update|600]]
>Looks like my system was already up to date.  The next step is installing Apache from the apt repository using the following command.  Apache is a very common long standing web server technology that is free and open sourced.
>```bash
>apt install apache2 -y
>```
>![[../images/08/server_activity_apache_install.png|Installing Apache Web Server|600]]
>Once Apache installation is complete, I use `systemctl` to start the apache2 daemon that will serve the default web page.  I also check that everything is running as expected using the status command from `systemctl`.
>```bash
>systemctl start apache2
>systemctl status apache2
>```
>![[../images/08/server_activity_start_apache.png|Starting the Web Server Daemon|600]]
>Everything looks to be in working order, so I open Firefox and navigate to http://localhost/ and observe that the default Apache page is served.  Notice that this page is served over HTTP and not HTTPS, therefore it is not using TLS encryption.
>![[../images/08/server_activity_http.png|Apache Default Web Page Over HTTP|400]]
>In order to set up TLS encryption on my Apache web server, I must make some quick configurations.  I use the `a2enmod` command to enable the SSL module.
>```bash
>a2enmod ssl
>```
>![[../images/08/server_activity_enable_ssl.png|Enable SSL on Apache|600]]
>The output suggests restarting Apache, but before I do that, I need to enable the default SSL site using the `a2ensite` command.  This command instructs Apache to use the default configuration file for SSL.
>```bash
>a2ensite default-ssl
>```
>![[../images/08/server_activity_enable_ssl_config.png|Enable SSL Apache Configuration|600]]
>Apache comes with a pre-installed self-signed certificate, but I want to make my own certificate using my own certificate authority.  I use `openssl` to create the CA which outputs an RSA key called `root-ca.key` and the CA certificate called `root-ca.crt`.
>```bash
>openssl req -x509 -nodes -newkey RSA:2048 -keyout root-ca.key -days 365 -out root-ca.crt -subj '/C=US/ST=Denial/L=Earth/O=Atest/CN=root_CA_for_firefox'
>```
>![[../images/08/server_activity_create_ca.png|Create CA and Key|600]]
>Next, I will create a server private key and certificate signing request (CSR) in a file called `server.csr` using `openssl`.  The CSR is needed before issuing a signed certificate and will be used in an upcoming command.
>```bash
>openssl req -nodes -newkey rsa:2048 -keyout server.key -out server.csr -subj '/C=US/ST=Denial/L=Earth/O=Dis/CN=anything_but_whitespace'
>```
>![[../images/08/server_activity_csr.png|Creating Certificate Signing Request|600]]
>The CA and CSR are created so I can now create a certificate from the CA.  To do so requires the use of the `root-ca.crt`, `root-ca.key`, and the `server.csr` files created in the last two steps.  The certificate created will be set to expire in 365-days and be named `server.crt`.
>```bash
>openssl x509 -req -CA root-ca.crt -CAkey root-ca.key -in server.csr -out server.crt -days 365 -CAcreateserial -extfile <(printf "subjectAltName = DNS:localhost\nauthorityKeyIdentifier = keyid,issuer\nbasicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage=serverAuth")
>```
>![[../images/08/server_activity_cert_generated.png|Generating Certificate|600]]
>The certificate signature outputs as "ok" so this certificate should be valid.  My next step is to load this certificate and encryption key into the private repository Apache uses in the default SSL configuration.  I will replace the existing ssl-cert-snakeoil PEM and Key files with the `server.crt` and `server.key` using the following commands.
>```bash
>cp server.crt /etc/ssl/certs/ssl-cert-snakeoil.pem
>cp server.key /etc/ssl/private/ssl-cert-snakeoil.key
>```
>![[../images/08/server_activity_update_keys.png|Replacing Default Keys with Generated Keys|600]]
>Everything should be now configured for the Apache web server to use SSL and our CA certificates.  To recap, I have installed Apache, installed, and enabled the SSL module, created a CA, and signed certificate, and replaced the default certificate and key with the generated ones.  The following command restarts the Apache server.  I also check to confirm that the status is active without errors.
>```bash
>systemctl restart apache2
>systemctl status apache2
>```
>![[../images/08/server_activity_apache_restart.png|Restarting Apache With SSL|500]]
>With Apache configured with SSL and restarted, I open Firefox and navigate to the default web page using TLS via  https://localhost.  However, this time I am presented with a security warning related to the certificate.
>![[../images/08/server_activity_warning.png|SSL Self-Signed Certificate Warning|375]]
>I receive this warning because browsers do not trust self-signed certificates by default, as they could have been created by anyone instead of a trusted CA.  While I could accept the risk and bypass this warning, it would be better to demonstrate how to get a browser to trust the certificate through importing my generated CA into Firefox.  I press the hamburger menu (three stack horizontal lines icon) in the upper right corner of the browser and select Settings.  While on the settings page, I search for the certificate and press the "View Certificates.." button which launches the Certificate Manager window.
>![[../images/08/server_activity_cert_settings.png|Searching For Certificate Settings|400]]
>The Certificate Manager Authorities tab lists all of the trusted CAs that came preinstalled with Firefox.  To add my generated CA, I select the Authorities tab and press the Import button at the bottom of the Certificate Manager window to launch the file manager window.
>![[../images/08/server_activity_cert_manager.png|Certificate Manager Authorities Tab|500]]
>I navigate to Other Locations on the left navigation bar and select the "Computer" button.  Then I scroll down and select the `root-ca.crt` file that I created using `openssl`.  Adding this file instructs Firefox to trust any certificate generated by my CA.  By importing my CA, the browser warning message should not be presented the next time I visit https://localhost.
>![[../images/08/server_activity_import.png|Import ROOT-CA.CRT Into Browser Store|600]]
>When importing the `root-ca.crt` file, Firefox asks me what I want to trust.  I select "Trust this CA to identify websites" as the CA is being used to generate certificates for websites, then I press OK.  I press OK again to close the Certificate Manager.
>![[../images/08/server_activity_trust.png|Trust CA Options|600]]
>With the CA imported into Firefox, I reload the TLS default page at https://localhost and see that there is not an SSL warning any longer!
>![[../images/08/server_activity_https.png|HTTPS Loaded  Successfully|500]]
>Apache and SSL are all set up now on my Ubuntu VM.  Next, I install ModSecurity by jumping back into my root terminal and using `apt` to install the needed packages.
>```bash
>apt install libapache2-mod-security2 -y
>```
>![[../images/08/server_activity_modsec_install.png|Installing ModSecurity Packages|600]]
>ModSecurity comes with a default configuration file but is named in a way that it will be ignored.  I  rename the recommended configuration file to one that is automatically picked up in the default configuration for ModSecurity.
>```bash
>mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
>```
>![[../images/08/server_activity_config_move.png|Enabling ModSecurity Default Configuration|600]]
>The default configuration has blocking mode disabled.  I want to ensure that malicious requests are blocked from reaching my Apache web server.  I replace the DetectionOnly setting with the "On" setting that ensures malicious requests will be blocked.
>```bash
>sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g' /etc/modsecurity/modsecurity.conf
>```
>![[../images/08/server_activity_blocking_mode.png|Enable ModSecurity Blocking Mode|600]]
>That's it for the basic ModSecurity configuration.  Because the Apache daemon is already running and I have made changes by installing and configuring ModSecurity, I need to restart Apache so that the changes take effect.  It takes about 30 seconds for ModSecurity to fully load.
>```bash
>systemctl restart apache2
>systemctl status apache2
>```
>![[../images/08/server_activity_restart_modsec.png|Restarting Apache With ModSecurity|600]]
>The daemon appears to be running without any issues since ModSecurity was installed.  I open Firefox and reload the HTTPS web page using `CTRL+SHIFT+R` to confirm it is still serving normally.
>![[../images/08/server_activity_modsec_happy_page.png|ModSecurity Loaded Page|500]]
>The page loads normally with ModSecurity running!  Now, I will use a classic cross-site scripting payload within the URL to test that the WAF is running in blocking mode.  The ModSecurity rule will detect this malicious string and block our HTTPS request.  This time I navigate to the site with the URL `https://localhost/?<script>alert('xss')</script>` and observe the Forbidden response!
>![[../images/08/server_activity_forbidden.png|Blocked Request By ModSecurity|500]]

### Threat Modeling
A fantastic process before, during, and after development is **threat modeling** where a vested group of individuals related to a project study the technology and examine how a malicious actor could attack and abuse the system.  Once a list of attack vectors is compiled, the team works out treatment plans to avoid or mitigate the security risks identified.  The benefit of doing a threat model prior to any development work is that it frames a developer's mindset to be security focused.  Eliminating security issues before they exist can save a lot of risk and money in the long run.  I am a fan of conducting threat models early and often with as many participants as possible.

The participants of a threat model will vary by the project and organization team members.  Ideally, the threat modeling sessions will include stakeholders from product, management, engineering, and security.  A complete threat model may not be accomplished in a single session and many hours of work need to go into it.  The more effort that is put into threat modeling typically yields higher quality and reduced security risks.  The process of a threat model is held as a meeting with an individual responsible for taking notes on risks identified, and possibly another individual responsible for creating a **data flow diagram (DFD)** which maps the elements of the how information flows through the subject technology.  Almost any diagramming software can be used for the DFD and I enjoy using the free application Diagrams.net.

The DFD consists of the elements *external entity* (rectangle), *process* (circle), *data store* (double sided rectangle), and *data flow* (directional arrows).  The following diagram shows each of these elements in which data flows from an entity towards a process.  A process could trigger another process or put information into a data store.  A process could also pull data from a data store and return it to another process or entity, and so on.  Each element would be labeled with the respective name of the item that will be used as reference points for discussions.  

![[../images/08/dfd.png|Blank Data Flow Diagram Used in Threat Modeling|400]]

> [!tip] Tip - Data Flow Diagram Size
> The level of detail and size of a DFD can become massive.  It is important for the initiator of the threat model to define the scope of the exercise and ensure that elements are not overly generalized or broken down into undue detail.  My rule of thumb for a threat model DFD is that it should comfortably fit onto one normal size computer screen and still be legible.  If you have to pan around to see parts of the DFD or squint your eyes and move close to the monitor, then the threat model/DFD scope is probably too wide and consideration should be taken to break it up into additional models.

After all the elements are mapped onto a DFD, the threat modeling group analyzes each element for ways it could be attacked.  This can be conducted one element at a time to ensure thorough completion, or it can be performed ad hoc.  There are a few techniques or models that can be used that have been thoroughly documented and available through internet resources.  I would leave it to the reader to research other threat model methodologies in addition to the **STRIDE method** that I discuss here.  STRIDE, which stands for *spoofing*, *tampering*, *repudiation*, *information disclosure*, *denial of service*, and *privilege escalation* is used as a template to apply to elements.  Threat model participants evaluate each element against STRIDE to tease out how it is affected and what could be done to mitigate its risks.  Under this model's context, not every element would be subject to each component of STRIDE.  For example, it is unlikely that an external entity such as a user, could be *tampered*.  The following table suggests which element applies with each component of STRIDE.

![[../images/08/stride2.png|STRIDE By DFD Element|750]]


>[!activity] Activity 8.2 - Threat Model
>Consider the following DFD for an authentication process of a basic web application and conduct a threat model using the STRIDE components as a guide.  I will give you the first one as an example: the risk of the user being spoofed by an attacker can be mitigated by requiring a password to prove the user's identity during login.  There are maybe another 25 risks given the number of elements and applicable STRIDE components.
>
>![[../images/08/dfd_login.png|DFD For Web Authentication|400]]

### OWASP Top 10 Risks
The *Open Web Application Security Project (OWASP)* is a nonprofit organization that supports the creation of web application security projects, tools, and standards.  One such project is the **OWASP Top 10** which lists the most common risks to web applications.[^1]  The list is updated every few years with new items being added, old items being removed, and existing items being reordered or updated.  

>[!info] Info - OWASP Application Security Verification Standard (ASVS)
>Another awesome resource from OWASP is their ASVS project which offers a detailed security framework for assessing web applications. [^2]  It enumerates hundreds of standards organized by control objective and provides levels of maturity and *common weakness enumeration (CWE)* references.  Driven by community developers, the ASVS can be used as an audit tool to assess the security posture of a web application, its systems, and development processes.

At the time of this writing, the 2021 version is the current version that includes the following risks in order of frequency:

1. **Broken Access Control** - Unauthorized access to software and its data
2. **Cryptographic Failures** - Exposes sensitive data
3. **Injection** - Allows input to be used as commands, code, and queries to cause the software to perform actions otherwise not intended
4. **Insecure Design** - Missing or ineffective control design of the software
5. **Security Misconfiguration** - Insecure settings that expose software to attack
6. **Vulnerable and Outdated Components** - Security issues in packages or libraries used within software
7. **Identification and Authentication Failures** - Defects in the proving of identity and session management
8. **Software and Data Integrity Failures** - Use of malicious or tampered code or data
9. **Security Logging and Monitoring Failures** - Inability to detect and respond to breaches
10. **Server-Side Request Forgery** - Server sends URL requests to unexpected destinations

This list is beneficial to developers and security professionals as it defines the risks modern web applications face.  It provides a risk model to teams when assessing their applications and known findings.  Most web application penetration test findings will reference or tie a finding back to the OWASP Top 10 list to support the rationale of the issue.  Developers should study these common risks and how they could be realized in their applications.  For instance, each of the items on the list comes with generalized examples and mitigations which serves as a basis for additional research.
### Software Composition Analysis (SCA)
Software is often built using third party libraries which contain packages of code that provide some extended functionality.  These packages are abstractions of what would otherwise be a complex undertaking to code independently.  The package is centered around a specific task or activity and can be thought of as a building block used to streamline the development effort because a developer will not have to build all needed functionality from scratch.  Each popular language has a *library manager* that also serves as a *repository* of all packages, such as NodeJS's *node package manager (NPM)* and Python's *pip installs packages (PIP)*.  Developers can download any published package from the repository and then use its functions within their own project.  Similarly, just about anyone can create a new package and upload it to the repository for others to use.  Packages can also be referred to as a *dependency* to a project since the package is needed for the application to function.  

> [!tip] Info - Packages Using Packages
> Software packages can themselves be used by other third-party packages.  This causes a layering, or nesting, of any number packages within packages.  The term **transitive dependency** is used to describe a deeply nested package within a project that uses a package that includes other packages.

All packages are subject to vulnerabilities such as the ones outlined in the OWASP Top 10.  Security researchers and developers may find vulnerabilities within a package and follow the responsible disclosure process outlined in the Security Systems chapter.  This would result in a common vulnerabilities and exposures (CVE) report for the package name and version, which can then be used by a special class of vulnerability scanner called **software composition analysis (SCA)**.  Such tools look at the manifest file that imports packages by version, or the installed packages themselves, and compares them to a database of CVEs.  If there is a match between the package version and a CVE, a finding is generated and alerted to the user of the scanner.  

The SCA tool can be run on the command line, installed as a plugin within an *integrated development environment (IDE)*, or integrated within development pipelines where code is merged and deployed.  While SCA tool results are usually thought of as very accurate, one criticism is that the vulnerabilities identified are almost always overstated.  For instance, a package might have a function that includes a command injection vulnerability, but if the parent project does not use that function, it avoids the practical exploitation of that dependency's command injection vulnerability.  The probability of a path to this exploitation decreases depending on how transitive the dependency is.  At the time of this writing, I am only aware of one SCA vendor (Contrast Security) that is able to identify vulnerable paths of packages through *reachability analysis*.  Their premium service is costly, as they have to employ an army of researchers to develop tools that identify each CVE's reachability, which is a laborious endeavor.

SCA can be used to generate *software bill of materials (SBOM)* which is a composed list of all the packages and their versions that make up the software project.  Many software due diligence efforts now focus on the availability or producibility of SBOM when evaluating the security wherewithal of software.  The process of a software development team to identify, select, use, and continuously evaluate packages is called *dependency management* which can vary in the level of formality between organizations.  There should exist some sort of diligence efforts by the developer to select packages believed to have good security hygiene and then periodically reevaluate them to ensure that each package does not fall below required standards.  Some of the criteria used in dependency management include, but are not limited to, popularity, maintenance frequency, community support, license compatibility, security responsiveness, and many more.
### Software Application Security Testing (SAST)
One way developers and security professionals detect vulnerabilities within code is through the use of a **software application security testing (SAST)** solution.  This class of tooling looks at the code statically, or without running it, and identifies vulnerable patterns by using a rules engine which can be a scan or a path analysis.  The engine uses a library of rules that have been crafted to detect patterns using regular expressions.  Some of these patterns identify the *sources* and the *sinks* of code within a file or even between files depending on the tool.  Consider the following PHP code block that accepts a user supplied GET parameter into the version variable which is eventually rendered on the page using an echo statement.

```php
<?php​
$version = $_GET['version'];​
if($version == 2) {​
     //do stuff​
}​
echo "Version: ".$version;
```

Continuing with the above example, a SAST scanner should identify a *cross-site scripting (XSS)* vulnerability with the `$_GET['version']` identified as the source and the `echo "Version: ".$version;` as the sink.  Many types of software vulnerabilities result in the mishandling of user inputs (sources) or the mishandling of outputs (sinks).  Unlike SCA, where vulnerabilities identified are rarely a false positive, SAST findings have a high volume of false positives due to the nature of their rules.  These rules are not great at identifying mitigations and the scanner outputs should be used as a guide during secure code reviews.

The following list outlines the broad categories of SAST scanners available in the marketplace today. [^3]  Each SAST tool deploys at least one of these strategies to evaluate code and find potential vulnerabilities.  

1. **Configuration** - Checks configuration files
2. **Semantic** - Syntax and susceptible functions such as `executeQuery()`
3. **Dataflow** - Tracks sources to sinks
4. **Control Flow** - Identifies dangerous sequences, race conditions, and validation misses
5. **Structural** - Evaluates code structure such as class design and declarations

>[!info] Info - Secret Scanning
>Another useful SAST-like tool is a *secrets scanner*.  Including secrets in source code is a bad practice because the secrets could be compromised due to unauthorized access to the code.  It is best to keep secrets within encrypted vaults where they can be retrieved at runtime to avoid this risk.  Secret scanning tools scan source code, development logs, and other sources for secrets such as passwords, keys, and authentication tokens.  They, too, run on a rules library which is usually comprised of regular expressions tuned to identify specific secrets.  A great opensource secret scanner is TruffleHog while the best enterprise solution I have found is developed by Cycode Security.

SAST tools vary in support for languages with some only supporting a specific development language.  They are a great resource to developers and can be installed within IDEs to provide close to real-time detections of vulnerabilities being introduced while a developer writes code.  When a detectable vulnerability is identified, the SAST scanner plugin will highlight the vulnerable code and offer recommendations to resolve.  These tools can also be added into version control systems and developer pipelines to detect and block vulnerabilities from being merged into code or released into runtime environments.

>[!activity] Activity 8.3 - Security Coding
>It is a basic practice for developers to run SCA and SAST scans during development processes.  Application security professionals use these tools too when conducting secure code reviews.  One of the most widely used tool platforms in this area is Snyk because of its quality, coverage, and security community support.  Their toolset, which includes SCA and SAST, has a broad range of language coverage and provides good results.  Better yet, Snyk offers their tool for free for individual non-commercial use and they support many in the community with sponsorships.  Thanks, Snyk!  I will demonstrate using Snyk SCA and SAST tools against a vulnerable by design node application called DVNA hosted on my Kali VM.
>
>After the Kali VM is launched in Bridge Adapter network mode, I log in and open a terminal to download the vulnerable by design Node application DVNA from its git repository.  This repository contains all the source code and the package listing that I scan using Snyk's SCA and SAST tools.
>```bash
>git clone https://github.com/appsecco/dvna
>```
>![[../images/08/snyk_activity_dvna_clone.png|Clone the Git Repository DVNA by Appsecco|600]]
>The next step is to acquire the Snyk CLI which is free to use but requires me to authenticate to their web site.  Creating a new account is very easy but requires a GitHub account.  Because I already have a GitHub account, I use it to register and login to Snyk.  If you are following along with this activity and do not have a GitHub account, I recommend that you set one up now (both GitHub and Snyk are free to register and use).  Creating a GitHub account can be done by navigating to https://github.com/signup?ref_cta=Sign+up&ref_loc=header+logged+out&ref_page=%2F&source=header-home and entering your email address, username, and password.
>
>With the GitHub account set up, I navigate to Snyk's login page https://app.snyk.io/login/ and press the GitHub button to login.
>![[../images/08/snyk_activity_snyk_login.png|Snyk Login Page|500]]
>After entering in my GitHub username, password, and authentication token sent to my email, I am presented with the Snyk web console.
>![[../images/08/snyk_activity_snyk_page.png|Logged In Snyk Home Page|500]]
>After I have logged into Snyk, I download the Snyk command line interface (CLI) tool from the terminal.  I make the tool executable and then move it into the binary folder so I can use it from any folder while in the terminal.
>```bash
>wget https://static.snyk.io/cli/latest/snyk-linux
>chmod +x snyk-linux
>sudo mv snyk-linux /usr/local/bin/snyk
>```
>![[../images/08/snyk_activity_download.png|Installing Snyk in Kali VM|500]]
>The Snyk CLI requires authentication before I can use it.  I have already logged into the Snyk website so that when I trigger the CLI tool authentication, I am presented with an authorization button.  If I were not logged into Snyk already, I would have to first login before hitting the authorize button.  I start the authentication sequence by first running the Snyk authentication command.
>```bash
>snyk auth
>```
>![[../images/08/snyk_activity_auth.png|Snyk CLI Authentication Initialize|600]]
>This command launches a browser tab where I press the Authenticate button to log the CLI tool in.
>![[../images/08/snyk_activity_authenticate.png|Authenticate Snyk CLI|500]]
>I return to the terminal after pressing the Authenticate button on the Snyk web page and see that the login was successful.
>![[../images/08/snyk_activity_auth_confirmed.png|Snyk Authentication Successful|600]]
>Now that the DVNA app is downloaded and the Snyk tool is installed and configured, I am ready to start scanning!  I start with an SCA scan against the DVNA package file targeted from the GitHub repository.
>```bash
>snyk test https://github.com/appsecco/dvna
>```
>![[../images/08/snyk_activity_sca_start.png|Beginning of SCA Scan Results|500]]
>![[../images/08/snyk_activity_sca_end.png|End of SCA Scan Results|500]]
>The scan downloads the `package.json` file, which contains all the packages built into DVNA, and scans each package version against the vulnerability database.  The SCA scan found 49 paths to vulnerable packages ranging from low to critical severities!  You may recall as part of the security vulnerability disclosure process that the maintainer of the code will release a security patch to cure the security vulnerability.  Therefore, most of these SCA vulnerabilities could likely be mitigated by updating the versions of the packages being used by DVNA.
>
>Next I run a SAST scan against DVNA's source code that was cloned locally.  I change the directory of my terminal to `dvna` and then run a Snyk code test.
>```bash
>cd dvna
>snyk code test
>```
>![[../images/08/snyk_activity_sast_start.png|Beginning of Snyk SAST Scan Results|500]]
>![[../images/08/snyk_activity_sast_end.png|End of Snyk SAST Scan Results|500]]
>Another 37 vulnerabilities were found in the source code with five of them rated High.  Mitigations to these vulnerabilities are not as easy as SCA in which a package version usually has to be updated.  SAST finding remediation requires more knowledge of how the application functions, as the fix should not break the functionality of the application.  Therefore, each finding has to be manually triaged and repaired using techniques unique to the class of vulnerability.  In the next chapter we will fix the source code of a few web application vulnerabilities.

### Dynamic Application Security Testing (DAST)
While SAST tools look at static code to find vulnerabilities, **dynamic application security testing (DAST)** tools scan running applications and look for vulnerabilities.  Imagine navigating to a site and sending a malicious GET cross-site scripting (XSS) payload to the application server.  The success of this payload may depend on how the web application was developed.  If it did not succeed, you could try another XSS payload with some slight modifications.  There are several hundred XSS payload variations you could eventually try.  Now imagine having to do this for every class of vulnerability for every potential input field on every page and you would quickly scale to hundreds of thousands of manual tests to run.  DAST scanners help to automate this type of security testing work by identifying pages, parameters and then attempting every configured payload type.

>[!tip] Tip - What Payloads To Try?
>Check out Swisskyrepo's PayloadsAllTheThings GitHub repository (https://github.com/swisskyrepo/PayloadsAllTheThings​) for a list of web application vectors and payloads. 

This class of tool first scans the application mapping out its structure, such as available pages.  It works much like a web crawler by identifying hyperlinks and following them until it has exhausted all available linked pages.  After the tool has mapped each page, it analyzes the page for input vectors such as HTTP headers, HTTP parameters like GET and POST, and storage locations like the cookie jar.  Then each input vector is tested with malicious payloads and the returned page is compared to a baseline page.  The differences between the pages are evaluated and if the malicious payload is found to have been successful, an alert is raised.  DAST scanners tend to miss a lot of vulnerabilities as they are unable to adapt to nuances of how an application functions.  They can often miss deep rooted pages that require special circumstances to be reachable.  However, they have a relatively low false positive rate and can find common application vulnerabilities with a high degree of accuracy.  These tools can only be run against live applications, which means their implementation is usually conducted post deployment in the SDLC.

>[!activity] Activity 8.4 - DAST Scan
>I will continue using the DVNA to demonstrate the use of a popular free-mium DAST scanner by PortSwigger called Dastardly in the Kali VM.  I will also launch DVNA as a containerized application, which is a convenient way to run an application without having to set up the system dependencies needed.  Dastardly will also run as a containerized app making it portable and usable on any system that has Docker installed.
>
>Because both DVNA and Dastardly run as containers, I will need to install Docker and configure it on my Kali VM.  Before I do that, I run updates on my system to make sure that all dependencies Docker will need are up to date.
>```bash
>sudo apt update -y
>```
>![[../images/08/dast_activity_update.png|Update Kali System|600]]
>With the system updates complete, I install Docker form the `apt` repository.
>```bash
>sudo apt install docker.io -y
>```
>![[../images/08/dast_activity_docker_install.png|Installing Docker on Kali|600]]
>After Docker is installed, I add my user to the Docker group using the `usermod` command as root.  This will allow my user to run Docker commands and run containers without having permissions issues.  After I run the command, I reboot and log back into the system so that my user's group change takes effect.
>```bash
>sudo usermod -aG docker $USER
>reboot
>```
>![[../images/08/dast_activity_docker_group.png|Adding User to Docker Group|600]]
>Now that Docker is installed, I can seamlessly download the DVNA image and run it as a container on my Kali host machine mapping the container's HTTP port 9090 to my host machine's port 9090. 
>```bash
>docker run --name dvna -p 9090:9090 -d appsecco/dvna:sqlite
>```
>![[../images/08/dast_activity_dvna_run.png|Running DVNA Container|600]]
>The DVNA maintainers created that downloaded image to run the application on start.  I can see that the container is running in the background with mapped ports 9090 using the docker container command.
>```bash
>docker container ps -a
>```
>![[../images/08/dast_activity_dvna_status.png|Listing Running Docker Containers|600]]
>Launching Firefox and navigating to localhost port 9090 greets me with a DVNA login page!
>![[../images/08/dast_activity_dvna_login.png|DVNA Login Page on Localhost Port 9090|500]]
>With DVNA running, I am ready to launch the Dastardly DAST scan against it.  Dastardly is a limited free tool maintained by PortSwigger.  It scans for only a few types of vulnerabilities and cannot be configured to use credentials to login into the DVNA application.  There are other scanners that can be used to perform authenticated scans, such as OWASP's ZAP if you are interested in exploring DAST tooling further.  Before I set up and run the scanner, I need to know the IP address of the host using the IP command.  I see that it is 192.168.4.167 and that there is now a docker0 interface.  This Docker interface is a virtual interface used between the host (Kali) machine and the Docker containers.
>```bash
>ip a
>```
>![[../images/08/dast_activity_ip.png|Kali IP Address on Ethernet Interface|500]]
>I will run Dastardly against the DVNA container using another Docker container.  The following command will download and run the Dastardly image from the public repository.  I instruct Docker to run as my current user and pass the present working directory as a shared folder to the running Dastardly container.  I feed the image the target URL using the host IP address on port 9090 where the DVNA application is reachable while specifying an output file that can be used to revisit the results of the scan.
>```bash
>docker run --user $(id -u) --rm -v $(pwd):/dastardly -e DASTARDLY_TARGET_URL=http://192.168.4.167:9090/ -e DASTARDLY_OUTPUT_FILE=/dastardly/dastardly-report.xml public.ecr.aws/portswigger/dastardly:latest
>```
>![[../images/08/dast_activity_start_result.png|Running Dastardly As Container Against DVNA|500]]
>![[../images/08/dast_activity_scan_end.png|Dastardly Output Vulnerable JavaScript Findings|600]]
>The scanner starts by mapping the site, then tests for security vulnerabilities from its limited test set that includes reflected XSS and vulnerable JavaScript dependencies. [^4]   After a few minutes of running, the scan is complete.  It was able to detect a few vulnerable JavaScript dependencies!

## Exercises
---


>[!exercise] Exercise 8.1 - Web Server Security
>In this task, you will install Apache web server on your Ubuntu VM using Bridge Adapter network mode and secure it with an OpenSSL self-signed cert and ModSecurity WAF.
>#### Step 1 - Install Apache
>Start your Ubuntu VM and open a bash terminal. Change directory to the root folder and switch to the root user. 
>```bash
>sudo su -
>cd /
>```
>Update the Ubuntu system so all required packages are up to date. 
>```bash
>apt update -y
>```
>Install Apache web server from the Ubuntu apt repositories. 
>```bash
>apt install apache2 -y
>```
>Start Apache web server on the Ubuntu VM.
>```bash
>systemctl start apache2
>```
>Open the Firefox web browser within the Ubuntu VM and navigate to the [http://localhost/](http://127.0.0.1/). Observe the default Apache page loads!  Update the default index.html page with your name and the date. Replace the NAME and DATE fields in the command below with your name and today's date.
>```bash
>echo "NAME DATE" > /var/www/html/index.html 
>```
>Revisit [http://localhost/](http://localhost/) in your browser and confirm that the new page loads showing your name and today's date.
>Update the default web page
>#### Step 2 - Configure Apache SSL
>Using your root user terminal, enable SSL on the Apache web server.
>```bash
>a2enmod ssl
>```
>Enable the default SSL site that installs with Apache. 
>```bash
>a2ensite default-ssl
>```
>Restart the Apache web server to enable the new site settings.
>```bash
>systemctl restart apache2 
>```
>Create a private certificate authority with the following command and observe that `root-ca.key` and `root-ca.crt` files are created.
>```bash
>openssl req -x509 -nodes -newkey RSA:2048 -keyout root-ca.key -days 365 -out root-ca.crt -subj '/C=US/ST=Denial/L=Earth/O=Atest/CN=root_CA_for_firefox' 
>```
>Create a private key and certificate signing request from the previously created CA certificates.  The private key will be used to secure the SSL site. Observe `server.key` and `server.csr` files created. 
>```bash
>openssl req -nodes -newkey rsa:2048 -keyout server.key -out server.csr -subj '/C=US/ST=Denial/L=Earth/O=Dis/CN=anything_but_whitespace' 
>```
>Create TLS self-signed certificate that will be used in the Apache SSL site configuration. Observe server.crt file created. 
>```bash
>openssl x509 -req -CA root-ca.crt -CAkey root-ca.key -in server.csr -out server.crt -days 365 -CAcreateserial -extfile <(printf "subjectAltName = DNS:localhost\nauthorityKeyIdentifier = keyid,issuer\nbasicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage=serverAuth")
>```
>Replace the default certificate and key for the site and then restart Apache. 
>```bash
>cp server.crt /etc/ssl/certs/ssl-cert-snakeoil.pem
>cp server.key /etc/ssl/private/ssl-cert-snakeoil.key
>systemctl restart apache2
>```
>Using the Firefox browser in the Ubuntu VM, navigate to [https://localhost/](https://localhost/). Observe the insecure TLS warning and detail by pressing the Advanced button.
>
>Add the certificate authority file we created earlier to Firefox's allowed CAs. 
>1. Press the "hamburger menu" (three stack horizontal lines icon) in the upper right corner of the browser and select Settings. 
>2. In the Settings page, search for Certificate and select "View Certificates..." to launch the Certificate Manager.  
>3. With the Authorities tab selected, press the Import button at the bottom of the Certificate Manager window.  
>4. Navigate to the root directory where we stored our certificates and keys by selecting Other Locations on the left navigation menu, and then Computer.  
>5. Select the "`root-ca.crt`" file and press the Select button in the upper right corner.  
>6. With the Downloading Certificate window launched, select "Trust this CA to identify websites", press Ok and then Ok again to close the Certificate Manager window.  
>7. Open a new tab in Firefox and navigate to [https://localhost](https://localhost/). 
>
>Observe the page loads without error and is secured using TLS (lock icon in URL bar)!
>#### Step 3 - Install ModSecurity
>Using the Ubuntu VM root bash terminal, install ModSecurity using apt.
>```bash
>apt install libapache2-mod-security2 -y 
>```
>Set up the ModSecurity configuration file based on the provided recommended config file.
>```bash
>mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
>```
>Update the configuration file to turn ModSecurity blocking mode on.
>```bash
>sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g' /etc/modsecurity/modsecurity.conf
>```
>Restart Apache so the ModSecurity updates take effect. Note that the command takes ~10 seconds to complete.
>```bash
>systemctl restart apache2
>```
>#### Step 4 - Test WAF
>Using the Ubuntu VM's Firefox browser, navigate to [https://localhost/](https://localhost/) and observe that the page renders without issue.
>
>Now, use a classic cross-site scripting testing payload within the URL. The Modsecurity rule will detect this malicious string and block our HTTPS request. This time, navigate to the site with the URL `https://localhost/?<script>alert('xss')</script>` and observe the Forbidden response! 



> [!exercise] Exercise 8.2 - Secure Coding
> You will run secure code tooling against the DVNA code base in this lab task using your Kali VM using Bridge Adapter network mode.
> #### Step 1 - Install DVNA
> Download the DVNA repository using git from the home directory of your Kali VM user.
> ```bash
> git clone https://github.com/appsecco/dvna
> ```
> #### Step 2 - Install Snyk
> *Note, you can skip the account creation sub-step if you already have a GitHub OR a Google account you would like to use with Snyk.*
> 
> Set up a GitHub account by navigating to https://github.com/signup?ref_cta=Sign+up&ref_loc=header+logged+out&ref_page=%2F&source=header-home and entering your email, a password, and a username. You may have to verify that you are not a bot and submit a token that is emailed to your email.  
> 
> Set up a Snyk account after you have created (or already have) a GitHub account by navigating to [https://app.snyk.io/login/](https://app.snyk.io/login/) and using the GitHub button and the Authorize Snyk button.
> 
> While logged into the Snyk website, enable Snyk Code for remote SAST scanning by navigating to Settings (left menu), Snyk Code (sub menu), Enable Snyk Code (bottom), and hit save.
> 
> Install the Snyk Linux binary and move it's location for ease of use.
> ```bash
> wget https://static.snyk.io/cli/latest/snyk-linux
> chmod +x snyk-linux
> sudo mv snyk-linux /usr/local/bin/snyk
> ```
> Authenticate with Snyk. After running the following command, a browser will launch prompting you to login to Snyk using your GitHub (or Google) account, sign in, and press the Authenticate button
> ```bash
> snyk auth
> ```
> #### Step 3 - Snyk SCA Scan
> Run a software composition analysis (SCA) scan against the dvna repository on Github. We are running this scan locally on the remote repository to avoid having to install NPM packages on our Kali VM. Observe that several vulnerabilities are discovered after a few seconds of analysis.
> ```bash
> snyk test https://github.com/appsecco/dvna
> ```
> Snyk should have several vulnerabilities of varying severity. Select one vulnerability that interests you and write a summary of its causes and impacts.
> #### Step 4 - Snyk SAST Scan
> Execute a static application security test (SAST) on the DVNA local repository using Snyk. Navigate to the `dvna` directory and run the following Snyk command. Results will appear after a few seconds of analysis.
> ```bash
> cd dvna
> snyk code test
> ```
> Identify another vulnerability different from the SCA scan and research its cause and impact. Write a summary of what you learned during your research.



> [!exercise] Exercise 8.3 - DAST Scan
> In this task, you will run a DVNA web application and scan it using Dastardly from your Kali VM in Bridge Adapter network mode.
> #### Step 1 - Install Docker
> Both Dastardly and DVNA will run in containers using `docker`.  Update your Kali VM to ensure that all required packages are on the needed versions.
> ```bash
> sudo apt update -y 
> ```
> After updates are complete, install the Docker packages.
> ```bash
> sudo apt install docker.io -y 
> ```
> Once `docker` is installed, add your Kali VM user to the `docker` group so it can run Docker commands without root.
> ```bash
> sudo usermod -aG docker $USER 
> ```
> Adding a user to a group will not take effect until the next time they log in.  Reboot your Kali VM and log back in to avoid issues launching Docker containers.
> #### Step 2 - Run DVNA
> Once your Kali VM account has logged in again with `docker` group permissions, open a terminal and run the DVNA Docker container. The image will download and the container will launch while forwarding port 9090 to the Kali host.
> ```bash
> docker run --name dvna -p 9090:9090 -d appsecco/dvna:sqlite
> ```
> Open the Firefox browser within the Kali VM and navigate to [http://127.0.0.1:9090](http://127.0.0.1:9090/). Observe that the DVNA is up and running!
> #### Step 3 - Run Dastardly Against DVNA
> From within your Kali VM terminal, look up the VM's IP address under interface eth0 to use as a target for Dastardly.
> ```bash
> ip a
> ```
> While the DVNA application is running locally on the Kali VM, launch a Dastardly container targeting the local DVNA server. Make sure to replace the `IP_ADDRESS` with the IP address of the Kali VM. Wait a few moments for the image to download and the scan to begin.
> ```bash
> docker run --user $(id -u) --rm -v $(pwd):/dastardly -e DASTARDLY_TARGET_URL=http://IP_ADDRESS:9090/ -e DASTARDLY_OUTPUT_FILE=/dastardly/dastardly-report.xml public.ecr.aws/portswigger/dastardly:latest
> ```
> After a couple minutes, the scan completes with a few low severity findings. Dastardly is unable to scan authenticated pages and tests for only a few vulnerability classes.  Using `cat`, display the vulnerabilities found from the DAST scan.
> ```bash
> cat dastardly-report.xml
> ```


[^1]:OWASP Top Ten; OWASP Foundation; March 8th 2024; https://owasp.org/www-project-top-ten/
[^2]: OWASP Application Security Verification Standard; OWASP Foundation; March 8th 2024; https://owasp.org/www-project-application-security-verification-standard/
[^3]: SAST Tools & Testing: How Does it Work and Why Do You Need it?; Snyk; March 9th 2024; https://snyk.io/learn/application-security/static-application-security-testing/
[^4]: Scan Checks - Dastardly, from Burp Suite; PortSwigger; March 9th 2024; https://portswigger.net/burp/dastardly/scan-checks