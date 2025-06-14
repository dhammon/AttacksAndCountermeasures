<span class="chapter-banner">Chapter 14</span>
# Mobile Application Security
<div class="image-crop">
  <img src="../images/14/android_armor.jpg">
</div>

**Objectives**
1. Describe Android application fundamentals and operating components.
2. Understand the security features and risks of Android applications.
3. Conduct basic static and dynamic analysis of Android applications using Qark and Android Studio.

Prior to artificial intelligence, web 3.0, and cloud technology trends, mobile applications were all the rage.  For many years it seemed that every organization was rushing to develop and offer a mobile application to their users.  During this surge of enthusiasm, many applications were developed that exposed security risks and new attack vectors against organization systems.  Mobile applications have persisted as a useful mechanism to connect individuals to existing and new organizations.  New organizations leverage the mobile ecosystem to launch businesses solely dependent on smart phone and tablet users.  Today, Apple and Android are the major systems that support mobile application development with the extreme majority of market share.  While both companies approach mobile applications differently, we will focus on the Android system in this chapter due to its relative ease to analyze.  Apple's walled garden architecture makes it more challenging to analyze mobile applications, usually requiring a MacOS with which not everyone may have access.  This chapter will describe the Android system and application basics and then walk the reader through the attacks and counter measures related to Android mobile applications.
## Android Application Basics
Understanding the development and operation of Android applications is important before discussing their security.  Application developers can choose to develop applications using Java, Kotlin, or C++ languages.  The source code is then compiled using the Android software development kit (SDK) into an Android package file with the extension `.apk`. [^1]  This portable file contains all the data, resources, and compiled code to run an application on an Android operating system.  The applications are signed digitally with a developer-maintained certificate before being uploaded to Google Play using a registered developer account.  Once in the store, they can be downloaded and installed by any internet user.

APKs are effectively archive files that can be installed manually on a device without the use of the Google Play app, known as *side loading*.  The benefit of installing an app from Google Play is that it must meet Google's privacy and security requirements; although there are plenty of malicious apps that are published at any given time.  

>[!warning] Warning - Sideloading Dangers
>It is inadvisable to install Android apps from third-party stores or to install manually through sideloading, unless the user has taken precautions or otherwise trusts the application source.

Applications running on an Android system, such as a smart phone or tablet, are run within a segregated process called a *security sandbox*.  This separation from other applications and core features of the operating system helps to minimize the impact a malicious application could have on a device.  We will explore how a misbehaving application takes advantage of Android components to exploit vulnerabilities in other applications later in this chapter.  The application is assigned a unique Linux user that only has access to that application's files using the operating system's UNIX file permissions set by the system.  When the application is launched, it is given its own process and runs in isolation from other applications running the environment.

Each app running in a sandbox is also granted least privileges by default.  Application developers have the ability to loosen permission controls on their application to allow various sources to interact with its components.  If mishandled, these less restrictive permissions could open up the application to security vulnerabilities.  Applications can also use other operating system APIs to utilize hardware components, such as contact lists or the camera.  Android ensures that these permissions are explicitly granted by the user when installing the app or during runtime for the more dangerous permissions.  You may have seen this as a pop-up message during app installations which gives the user the ability to allow or deny application permissions.

The graphic below attempts to illustrate some of the previous points.  There are three applications titled A, B, and C (light blue boxes) running within sandboxes on top of the operating system (bottom grey bar).  The operating system maintains each of the application's permissions describing what the application is allowed to access.  In this table, on the bottom left of the graphic, App C has permissions to the camera, which is also depicted using a camera icon within the app on the right.  The operating system also maintains databases, like SQLite, the file system, application users and manages running processes.  As we will learn in the following section, each application has components that can be invoked using *intents*.  

![[../images/14/app_runtime.png|Android Application Runtime Environment|600]]

Each application's access to these components is established during development.  They restrict an application's ability to interact with other applications as shown between App A and App B's blocked arrow.  In this example, App B attempts to directly interact with App A, but is unable to do so because of sandboxing and missing permissions.  Applications can also allow interactions with other apps, as shown between App B and App C.  Here, App B interacts with the Activities component of App C through the intents system illustrated with green arrows.
### Components of Android Applications
Interacting with an application can be performed through its **components**, which act like services engaged by the user or other events such as from other applications or the operating system.  While every app can use components, not every app is built with each of the capabilities the components provide.  Developers chose which components are needed based on the functionality of the app as well as their configurations, such as permissions.  Having a basic understanding of each of the four components is important from the security perspective, as they are part of the application's overall attack surface because they provide a means to interface with the application.

The **activities** component is the most recognizable component for an Android application because it serves as the user interface.  Any application you have used has a rendering on the screen that presents data and objects like buttons and fields.  This screen, or view, is an activity component that receives events, such as inputs like touches or clicks, which trigger program logic within the application.  Activities can even be triggered by other applications provided the activity is exported with the appropriate intent filters and permissions.  The system interacts with the application through activities while tracking what is on the screen, the processes that start and stop activities, handling of process state, and implementing the user flows between activities as each view transitions to the next.  You can almost think of an app like a web site where each page on that site is the equivalent of an activity.

Many applications allow for features to run in the background while you use another application.  A common example of this is listening to a music app (in the background) while you have another application in focus, such as a maps application.  Applications handle running applications in the background through the **services** component.  Services also support long-running operations and remote processes.  They lack a direct user interface and can be classified as a *started service* or a *bound service*.  Started services will terminate when the background process is complete, whereas a bound service remains open for another application or system.  Bound services are akin to an open port and service waiting for a connection to begin processing a request.

>[!info] Info - Android Fundamentals Documentation
>Android maintains excellent documentation covered throughout this chapter.  Interested readers are encouraged to read the full documentation at https://developer.android.com/guide/components/fundamentals .

The **broadcast receivers** component handles the reception of events sent from the operating system outside the regular user flow.  Therefore, this component again does not have a direct user interface but is triggered through announcements made by the system via *intents*, which will be covered in more detail in a later section.  A classic example of receivers is the notification of low battery, which is derived from system monitoring and sent to all applications.  An application may require a certain level of battery consumption and if the device is low on battery, it may need to handle the event gracefully and shut down the app.  When the system broadcasts the message, the application's broadcast receiver ingests the event and processes it.

The last component to know about is the **content provider**, which handles interactions with  the device's content.  This content is a shared set of application data typically stored in the device's file system or internal SQLite database.  Content providers also handle persistent storage locations dedicated to the application's sandbox environment.  Applications with explicit or implicit permissions can query or modify data stored within the content provider.  A great example of a content provider is a phone's contacts, as many applications request or require access to this dataset.  Content provider data location is managed using a URI namespace that is also used to manage permissions to the data.  Applications map data to URI namespaces providing access to other principals or applications.

I have mentioned the term **intents** a few times in this chapter already without defining it.  In order to discuss intents in further detail, a basic background of components is required.  Now that we've covered the components, we can begin to understand how intents are used in the Android system.  Intents are used by the system to activate components and can be thought of as the way the system sends inputs to the application.  When a user presses an application's button within an activity component, the application code typically creates an intent to launch the next activity when the user interacts with the app, also called *user flow*.   Similarly, any application can start another application's component, assuming permissions allow it, through intents from the system.  Intents are asynchronous messages used for activities, services, and broadcast receivers.

>[!warning] Warning - Implicit Intents
>Implicit intents can be sent by any application and are dangerous as it allows arbitrary applications on a device to intercept or spoof the intended component interactions!

When developing an application, engineers must include the components and permissions they plan to need.  All the components, and their permissions structure, among other information, are configured within the **manifest file**.  This XML document provides information, such as the minimum SDK version needed to run the application, as well as the version of the application.  The file itself is named `AndroidManifest.xml` and is a great resource to understand basic functionality and attack surface of a subject application.  The file is located at the root of the application's directory and is commonly extracted while reverse engineering an application to study how it works.  We will extract a manifest file in a later activity and review its contents that will look similar to the image below.

![[../images/14/manifest.png|Android Application Manifest File|500]]

The last major item to understand before we start exploring Android security are the **application resources**.  You can view the app's resources as all the rich content brought into the application, such as images, audio files, and formatted layouts prepared in XML format.  Sometimes, malicious applications might attempt to hide payloads in resources as an obscure place a malware analyst might not think to look!

>[!activity] Activity 14.1 - Mobile App Risk Assessment
>Individually, or in a small group, analyze what you now understand about mobile applications and determine their:
>- attack surface
>- impact of exploitations
>- mitigations 
## Defending Android Applications
Android has many built-in security measures and capabilities within the operating system.  Developers are expected to understand and use these features to protect their applications and data.  Carefully configuring the application to leverage such utilities ensures that the application's attack surface is minimized and reduces the impact of attacks.  This chapter has already mentioned some of these security measures, such as permissions and sandboxes, but it is worth exploring them in further detail.  The goal of this section is to further define each security item and some of their common pitfalls.  It can be easy to misconfigure an application to be vulnerable, so having a strong understanding of the available options promotes good application security hygiene.

>[!info] Info - Android Security Guidelines
>Most of the following topics were derived or inspired by Android's published Security Guidelines.  Their awesome documentation is worth a read!  https://developer.android.com/privacy-and-security/security-tips

There are several **native security** measures in place to protect applications and the overall system.  Because Android is based on a version of the Linux kernel, it inherits many of the security functionalities of that operating system.  This includes memory management protections that we explored in the Operating System Security chapter, such as ASLR and NX, as well as error protections.  Also discussed in that chapter, which also applies to Android, is the file system permissions that control access to files on the system.  Android extends permissions by creating a defined user for each application.  The user is constrained to only access that application's files and folders while also running in a sandbox that is segregated from other processes running on the device.  The system provides not only this permission structure but also includes application frameworks for cryptographical operations and an *interprocess communication (IPC)* that is native to the environment.

Applications may interact with remote and local **data storage** in a secure way that prevents unauthorized access.  There is an underlying concern that protected data could be accessed by other apps, but Android offers ways to mitigate this risk.  The three storage mediums to consider are internal storage, external storage, and content providers.  *Internal storage* is storage native to the device, such as flash media that is soldered onto the main board.  By default, internal storage is protected but can be overridden using the `MODE_WOLRD_WRITABLE` and `MODE_WOLRD_READABLE` permission flags, or by using a `FileProvider`.  These flags open the data to be read or written by any application on the device and should be used with caution.  

>[!warning] Warning - Storage Scope Creep
>Sometimes it is the intent to make the application's data available for other applications because the data is benign.  However, through the expansion and development of an application, that storage could be used to house more sensitive data in the future while forgetting that the permissions allow for world readable.  I have seen applications that misused shared storage like this, which were ultimately used as an input source into the application that introduced injection flaws.  Be very cautious of such storage use and scope creep!

*External storage* that is added to a device, such as through insertion of a micro-SD card, is always world readable and writable in older Android versions.  Trusting data on this storage medium that is to be used by the application is precarious given its open nature to the rest of the system's applications.  Modern Android versions use `scoped storage`, which limits access from other applications installed on the device.

The last data storage type, *content providers*, was explored in the previous section and included media like the file system and SQLite database.  The content provider access configuration for the application can be established using the `android:exported` flag.  Setting this flag to false prevents other applications from reading its data.  Access to the content providers can be controlled at a more granular level using the `android:grantUriPermissions` setting where the URI is a defined path that enables a developer to allow some access to files while denying access to others.  When using a SQLite database content provider, developers should make use of native provider functions `query()`, `update()`, and `delete()`, alongside the `selectionArgs` parameter, for parameterizing queries and preventing SQL injection vulnerabilities.

>[!tip] Tip - Raw SQL Concerns
>Raw SQL queries written into source code should be heavily scrutinized, if not fully avoided.  Technically, a raw SQL command may accomplish a database call, but if inputs or parameters are used within the query through concatenation that are not treated, it could expose the application to a SQL injection vulnerability much like what was covered in the Web Application Attacks chapter.

Using **permissions** throughout the components of the application is important to minimize information disclosure risks.  Failure to follow the principle of least privilege in permission settings could result in exposure of data through IPC calls that would otherwise have been protected.  Most of these permission settings can be found within the component blocks of the manifest file for the application.  The manifest file is an important security artifact as a means for measuring the security posture of an application's permissions.

Applications commonly use HTTP to make requests to internal and external resources.  HTTP is a versatile and useful protocol that most web technologies are built on, so it makes sense that a mobile application would rely on it.  However, HTTP is insecure by default, as its data is exposed in plaintext and can even be modified while in transit.  **Network security** becomes an important factor when securing Android applications and professionals should require all network connections be made over encrypted channels.  The `HttpsURLConnection` function should be used over HTTP.  The function `SSLSocket` should also be used to wrap encryption around other protocols and communications.  It is possible to make network calls using `localhost` but should be avoided in favor of using IPC given its security features within the operating system.  Applications should distrust any data or files downloaded using HTTP or through SMS as they are not encrypted.

Mobile applications are subject to many of the same types of input attacks that web applications are, which were introduced in the Web Application Attacks chapter.  Applications expect inputs from untrusted sources, including users, events from other applications, and broadcasts.  You may recall from the Web Application Attacks chapter that many of the injection attacks can be mitigated at the source through proper **input validation** where data is checked to meet expected criteria before being logically processed.  

>[!warning] Warning - Trusting Untrusted Input
>It can be challenging for developers to determine the trustworthiness of inputs and their sources.  Many developers will inherently trust data coming from the operating system or controlled data sources that are adjacent to their project, such as databases.  These sources may even be part of the overall application; however, second order attacks through such sources are common and difficult to spot.  Therefore, it becomes prudent to validate inputs regardless of if they come directly from a user or not.

When mobile applications started gaining in popularity, many organizations needed to make a strategic decision to offer a mobile application.  However, mobile devices also have internet browser applications such as Chrome installed that can be used to navigate web pages.  These built-in browsers can be used to access an organization's website and could offset the need to develop a dedicated mobile application.  Yet, often these web sites were designed with the expectation of being viewed on a monitor and not a small device like a smart phone.  In response, organizations began adapting their web sites using *responsive design* techniques through cascading style sheets (CSS) that rendered views depending on the size of the screen being used.  In addition, many organizations have complex dynamic web applications that they did not want to re-create for a mobile site, so responsive design solved these small screen issues.  However, market pressures driven by customer behavior still compelled organizations to develop and deploy mobile applications.  

To avoid having to re-write entire applications, many organizations leveraged their existing mobile friendly web applications into the **WebView** feature of Android.  The WebView is a frame within a web application activity or view that renders a website within the mobile application.  This trick streamlined the adoption of mobile applications for many organizations.  The user experience is typically good, and they often don't realize that they are looking at an embedded website inside a mobile application.  However, the use of WebViews exposes a mobile application to the same risks browsers and websites face which only compounds the overall mobile application security risk.  Ideally, WebViews have JavaScript disabled to avoid issues like cross-site scripting attacks.

**Credential security** is another factor to contemplate with mobile applications. You may have logged into a mobile application using credentials to access the application's features and content.  Chances are that the form you entered these credentials into was actually a WebView to avoid exposing the credentials to the mobile application directly.  But mobile applications could also store credentials into stores and processes in lieu of using a WebView.  If an application's design relies on local authentication, versus through a WebView, it is important that it leverages the native `AccountManager` feature of Android, which acts like a credential vault.  Never store the credentials as plaintext in a content provider to avoid the potential impact of another application gaining access to them.

>[!warning] Warning - Dynamically Loaded Code
>Updating applications through the Play Store can be a chore and some developers might have the idea to avoid having to submit version changes through the application store altogether by dynamically loading executable code from a remote location.  This practice is very dangerous as it provides an opportunity for a stealthy remote code injection.  Such a setup could go wrong in many different ways and could cause the application to be fully compromised.  The attacker could gain control over the remote resource or could trick the application into accepting an update from another resource.  Using the Play Store provides some level of protection against this, and dynamically loaded code should be considered insecure.
## Attacking Android Applications
This section provides an overview of approaches and methodologies for attacking mobile applications.  It will analyze the attack surface of mobile application architecture and system design while demonstrating some of the risks and vulnerabilities applications face.  In the last part of this section, we explore methods of statically and dynamically testing an Android application's security to discover weaknesses and vulnerabilities.
### Components Attack Surface
Many mobile applications are really wrappers of a web application or would otherwise rely on remote internet services to store and retrieve data that the application uses.  Imagine a social networking mobile application that is launched and displays content and messages from other users.  This information wouldn't be readily available within the device's storage and would have to be retrieved from the application's web servers.  Researchers can identify these web endpoints in a few ways, such as by monitoring traffic from the device or decompiling the application and searching for IP addresses and *fully qualified domain names (FQDN)*.

![[../images/14/vuln_api.png|Attacking Application HTTP APIs|450]]

The diagram above demonstrates a mobile application (App B) making network connections to internet resources.  Given the distributed nature of mobile applications, these internet services can be reached by any anonymous users.  Attacking *application program interfaces (API)* is beyond the scope of this chapter but is absolutely part of the attack surface of a mobile application.  Malicious actors can attack the API web endpoints directly, which should require strong authentication, authorization, and encryption to mitigate the effects of most attacks.

>[!story] Story - Social Media Application
>Once, while I was learning about mobile application security, I targeted a new social media application that was recently published onto the Play Store.  After downloading the application and decompiling it, I hunted for any remote endpoints the application would connect to.  I found an IP address and loaded it into my browser and was presented with an "Index of" page that listed the web server file contents of the web root directory.  It included a `stage.zip` file which I downloaded and unzipped.  This folder contained the raw source code of the mobile and web applications, including a configuration file that included plaintext secrets to the application's database, integrations with email and social media systems, and other credentials.
>
>Alarmed by my discovery, I contacted the application's developer listed in the Play Store and notified them of the sensitive files in a responsible manner.  I suggested they remove the zip file and rotate all credentials, as they would likely have been exposed and would be abused. 

Mobile application security can be challenging, as the attack scenarios may not be intuitive.  Vulnerabilities in a web application could lead to a system, network, or data breach in an organization, whereas vulnerabilities within a mobile application typically affect the client.  Developers could take this into consideration and lower security expectations thinking that a mobile device user wouldn't have the need or desire to exploit vulnerabilities within their own device.  It might not be obvious how a malicious actor could interact with a mobile application installed on a user's device, especially if that application doesn't use components that directly ingest events from remote sources like an incoming SMS message.

The basic threat model to exploit mobile application vulnerabilities consists of a malicious application installed on the same device as the victim application.  The malicious application will be designed to send malicious payloads to the target application with the intent to steal or modify data or take advantage of the victim's trust of the vulnerable application.  A victim might think they are interacting with their trusted application, but the vulnerable application could be completely compromised.  The following diagram shows the paths of a malicious application's interactions with a vulnerable application and its content providers.

![[../images/14/mal_app.png|Malicious Android Application Interactions|600]]

Malicious applications will send payloads to the vulnerable application through the operating system's intents.  This requires that the vulnerable application to have components with generous permissions which chain together with other vulnerabilities to achieve some impact.  These impacts will vary depending on the victim application's context and severity of vulnerability that we will explore in the next section.  

Vulnerable components could allow an attacker to start an authenticated user flow without having to know the user's credentials, or access data stored on the device that isn't directly accessible by the application.  In 2017, a popular ride sharing company was alleged to have been spying on driver's use of a competitor's mobile application.  This may have been accomplished through vulnerabilities within the competitor's mobile application.  Allegedly, the popular ride-sharing company used their application to collect data from the vulnerable competitor's application! [^2]
### Application Vulnerabilities
There are many types of mobile application vulnerabilities that can be identified through analysis of the application.  Mobile application penetration testers and security researchers define these vulnerabilities into risk types, such as those found in OWASP's Mobile Top 10 (https://owasp.org/www-project-mobile-top-10/).  We've mentioned a few of the risks already throughout the chapter and will highlight more common vulnerabilities in this section.

A mobile application might accept an input used to run commands on the operating system's sandbox through *command injection*, which is caused by failure to validate input or use safe functions or APIs for executing system commands.  This results in the attacker's ability to access and to modify any data being processed by the application's memory or files.  Such a vulnerability could be further leveraged by an attacker to achieve a reverse shell onto the victim's device where they can attempt further exploitations to escape the application's process environment.

It is also common to find *information disclosures* within a mobile application's decompiled source code.  This can include secrets used to authenticate with remote systems and other proprietary information of the developer's organization.  Hardcoded secrets are far too common, even in mature organizations.  Similarly, *path traversal* vulnerabilities can be exploited to gain access to files that are meant to be protected from general access in the application.  This is a result of mishandling permissions, as well as a failure of input validation on requests to content providers.

Many applications use the built-in SQLite database to store and process data within tables that are protected from access by applications.  However, raw SQL statements, which don't use parameterized requests, could expose all the data within an application's local database to an attacker.  The risks of a *SQL injection* on the local database are higher when that data contains sensitive information, such as personally identifiable information of contacts, or is used to store secrets in other applications like banking information.

The last vulnerability and exploitation worth considering is *tapjacking*, which is similar to web site clickjacking attack.  Tapjacking attacks overlay invisible elements over application functions that will perform some activity when the user presses the element.  Because the malicious invisible element is in the foreground and is placed over the victim's application, anytime the victim user attempts to interact with the vulnerable application, they are actually engaging with a malicious element.  The malicious actor exploiting this attack can use those taps by the user to send requests to other systems.  It could be as benign as tricking the user to "like" something on a social media app, following an advertisement link on which the attacker collects money, or as bad as hijacking authenticated requests connected to sensitive systems.  Tapjacking occurs when an application fails to implement safeguards against malicious user interface overlays, such as by allowing all permissions like `SYSTEM_ALERT_WINDOW`.

  <br>


### Enumerating Applications
The last section of this chapter explores some tools and techniques that can identify vulnerabilities within Android applications.  Using my Android application Modern Portfolio Theory as the target, I will conduct static and dynamic analysis to find several vulnerabilities throughout the application.  Our efforts will use several open source and free tools enabling us to enumerate and exploit weaknesses in the application.

>[!story] Story - Newton Analytics - Modern Portfolio
>I found an interest in developing web and mobile applications related to finance that laid the foundation for what would eventually become my career in cybersecurity.  The inspiration for developing the Modern Portfolio application came during my time studying portfolio management with Professor Hamid Ahmadi.  It was developed during a time when I was learning about mobile applications and certainly didn't understand the security implications covered in this chapter, making it an excellent opportunity to find vulnerabilities!  
>
>While Professor Ahmadi's class was focused on finance and not computer science, it introduced me to advanced Excel and Visual Basic for applications.  Like many of Professor Ahmadi's students, I drew great inspiration from his intellect and teaching style, and I am proud to include this application as the target in this chapter.  Sadly, Professor Ahmadi passed away a couple of years ago at the time of this writing.  He was brilliant, inspirational, and will be sorely missed.  Thank you Professor, you touched the lives of many students, especially myself.   

As we have explored during other sections of this text, static analysis typically consists of the review of an application that is not running.  Our static analysis of a mobile application will include unpacking, disassembling, and decompiling an application and then reviewing its source code and configurations, including the manifest file.  Obtaining an APK is relatively easy through online downloaders such as on https://apkcombo.com/ or by using the Google Play CLI, which will require a Google account.  Once acquired, the APK is inflated, and its Java archive files are disassembled and decompiled into human readable formats.  

There are several tools that can assist in the extraction of an application's source code, including the Quick Android Review Kit (QARK).  Qark includes the reverse engineering tool Smali that performs the disassembly and decompiling that reveals the app's source code.  Interested readers should checkout Payatu's great write up on how Smali works at https://payatu.com/blog/an-introduction-to-smali/.  After the source code files are obtained, we can manually review the source for potential vulnerabilities, misconfigurations, and information disclosures.  Qark also performs a vulnerability and misconfiguration scan which can be used as a starting point for finding issues within a targeted Android application.

  <br>



>[!activity] Activity 14.2 - Static Analysis Using Qark
>In this activity, I will demonstrate the acquisition of the Modern Portfolio APK and its static analysis using Qark.  After starting the Kali VM in Bridge Adapter network mode, I open a browser and navigate to https://androidappsapk.co/apkdownloader.  I then search for `newtonanalytics.modernportfoliotheory` and follow the link of the Newton Analytics application.  The site's page loads, and I press the download button for the latest version avoiding any ads.
>![[../images/14/static_activity_download.png|Downloading APK|550]]
>Still within the Kali VM, I open a terminal and clone the Qark GitHub repository.
>```bash
>git clone https://github.com/linkedin/qark
>```
>![[../images/14/static_activity_clone.png|Cloning Qark Repository|550]]
>Once cloned, I change my working directory to the `qark` folder and set up a python virtual environment.  Qark is fairly old and requires many outdated packages in Python to run, so setting up the application in its own virtual environment protects any dependency conflicts with my Kali host's Python installation.
>```bash
>cd qark
>virtualenv -p python3 venv
>source venv/bin/activate
>```
>![[../images/14/static_activity_env.png|Setting Up Python Virtual Environment|600]]
>Notice how the CLI prompt changes to include `(venv)` which signals we are in the virtual environment.  I can leave the environment anytime by running the `deactivate` command returning me to the host's CLI.  Qark comes with a `requirements.txt` file that lists all the packages and versions needed to run the application.  Using pip, I install Qark's required packages.
>```bash
>sudo pip install -r requirements.txt
>```
>![[../images/14/static_activity_requirements.png|Installing Qark's Requirements|600]]
>Everything seems to install without error except the `egg_info` module, which will be fine for this demonstration.  Qark also comes with a `setup.py` file which I run to complete the installation.  The setup file warns me of the deprecation of the install command.  However, it seems to install normally, so I disregard it for now.
>```bash
>sudo python setup.py install
>```
>![[../images/14/static_activity_setup.png|Setup Qark|600]]
>With Qark now installed, I'm ready to analyze the APK downloaded at the beginning of the activity.  Running the tool decompresses and decompiles the application before analyzing it and producing a report of any findings.
>```bash
>unzip -d ~/Downloads  ~/Downloads/newtonanalytics.modernportfoliotheory*.zip
>sudo qark --apk ~/Downloads/newtonanalytics.modernportfoliotheory*.apk
>```
>![[../images/14/static_activity_qark_run.png|Running Qark on Modern Portfolio|550]]
>After a few moments, Qark completes decompiling and analyzing the application and outputs a path to a generated report.  I notice that the `egg_info` module failed, which is expected, because that module errored when it initially installed.
>![[../images/14/static_activity_report_path.png|Qark Scan Completion|550]]
>I copy the path of the report and open it in my Kali VM's Firefox browser since it is an HTML report.  The report isn't too fancy but includes many findings from various Java files that were decompiled by Qark.  The issues format includes a header, description, and a link to the file and line number where the problem was found.
>![[../images/14/static_activity_report.png|Qark Report Results|600]]
>The third issue, titled `INFO Hardcoded HTTP url found`, displays an HTTP link to the newtonanalytics.com domain.  Seeing HTTP used without TLS is definitely worth calling out since traffic is unencrypted.  But this issue also informs us of remote resources that might also be worth investigating.  A humble request from my readers here, this domain is my domain, and I would appreciate it if you refrained from attacking it.  Thank you in advance!
>
>It is worth exploring this issue's source code since Qark decompiled it.  I return to my terminal and navigate to the `build/qark/cfr/newtonanalytics/modernportfoliotheory/` directory from my present working directory `qark`.  Listing out the contents shows several Java files appearing to be application components.
>```bash
>cd build/qark/cfr/newtonanalytics/modernportfoliotheory/
>ls
>```
>![[../images/14/static_activity_path.png|Listing Decompiled Files|600]]
>That hardcoded HTTP URL was found in the `Run.java` file on line 95.  Displaying the file using `cat` and scrolling through its content, I can see the FQDN endpoint!
>```bash
>cat Run.java
>```
>![[../images/14/static_activity_url.png|FQDN Manually Found|600]]
>Looks like the application is concatenating several parameters and rendering the page results in a WebView.  There might be a server-side request forgery (SSRF) or another type of path manipulation vulnerability here which would require dynamic testing.  Above the FQDN, I also spot some database references, so this application is likely using the native SQLite database.
>
>It is also worth exploring the application's manifest file content for more context on the components being used by the application and to potentially spot any over permissive settings.  The `AndroidManifest.xml` file can be found in the `build/qark` folder listed here.
>```bash
>cd ~/qark/build/qark
>```
>![[../images/14/static_activity_list.png|Listing Application Files|575]]
>I dump the contents of the manifest file to the terminal's standard output using cat and explore it further.  I find that the output includes a few activities as well as information about the application's version.
>```bash
>cat AndroidManifest.xml
>```
>![[../images/14/static_activity_manifest.png|Dumping AndroidManifest.xml File Contents|575]]
>I have only just scratched the surface of my static analysis and have already learned so much about the application.  In a full demonstration, I might run SAST tooling against the source code, enumerate all Qark's findings, and map out the entire application's logic flow.

Once static analysis is performed, the next step is to evaluate the application at runtime through *dynamic analysis*.  It is best to run the application in a development environment with an emulator as other tools can be installed on the host system to monitor the application.  Examples of this include BurpSuite or Wireshark which can capture network requests for analysis of the running application's behavior.  The Android Studio integrated development environment comes with many useful tools for debugging Android applications, such as its built-in emulator and the Android Debugger (ADB).  

These tools will enable the researcher to load the acquired APK into a virtual environment along with console access to the virtual environment operating system.  Monitoring an application's behavior enables interactivity and lays the foundation of developing proof of concept exploits and effective payloads that would otherwise be difficult to craft confidently during static analysis.

>[!activity] Activity 14.3 - Dynamic Analysis Using Android Studio and ADB
>Android Studio offers developers an integrated development environment with device emulators and built-in debugging tools.  In this activity, I will setup Android Studio on my Windows host and dynamically analyze the application using the Android debugger ADB.
>
>From my Windows host, I open a browser, navigate to https://developer.android.com/studio, and press the "Download Android Studio" button.  It is about 1GB in size and takes a few minutes to complete.
>![[../images/14/dynamic_activity_download.png|Downloading Android Studio Installer|650]]
>Once the download is completed, I open my Downloads folder and double click on the Android Studio executable to start the installation.  The installer requires administrative permissions causing the UAC prompt to launch.  I accept the UAC and then press Next to begin the installation.
>![[../images/14/dynamic_activity_setup.png|Starting the Installation of Android Studio|400]]
>The setup wizard walks me through the installation where I make sure to select the components "Android Studio" and the "Android Virtual Device".  I accept the default installation location and any other default recommendations.  Once finished, Android Studio launches and presents me with the "Welcome to Android Studio" view.
>![[../images/14/dynamic_activity_welcome.png|Complete Installation of Android Studio|700]]
>>[!note] Note - Missing SDK
>>It is important that the Android software development kit (SDK) is installed.  Sometimes Android Studio doesn't install the SDK by default.  If so, you would be presented with the "Missing SDK" window instead of the "Welcome to Android Studio" screen.  Make sure to install Android SDK - Android API 34 if you are following along!
>
>I'll be using the virtual device Pixel 3a with API 34 for dynamic analysis.  Options to set up a virtual device are found under the More Actions dropdown menu in the main pane of the Welcome to Android Studio screen under the "Virtual Device Manager" option.
>![[../images/14/dynamic_activity_vdm.png|Selecting Virtual Device Manager|550]]
>The Device Manager window lists all devices that are ready to be emulated.  To add a new device, I press the "Create Device" button in the top left corner of the window.  I choose the Pixel 3a hardware and press Next.
>![[../images/14/dynamic_activity_hardware.png|Selecting Hardware|700]]
>Then I select the API 34 image that will be installed on the virtual device and press the download icon.  The API is about 1GB in size and takes some time to download and install.  
>![[../images/14/dynamic_activity_image.png|Selecting Image|700]]
>The interaction also requires me to accept the license agreement, but eventually installs the related SDK.
>![[../images/14/dynamic_activity_sdk_install.png|SDK Installation|700]]
>Once the API and SDK are downloaded and installed, I return back to the Android Virtual Device wizard and name the AVD `Pixel 3a API 34` before finishing the setup of the device.
>![[../images/14/dynamic_activity_avd_finish.png|Complete AVD Setup|600]]
>Now that Android Studio and the SDK are installed, along with setting up an AVD, I am ready to launch the emulator.  From my Windows host I open a command prompt and navigate to the SDK's emulator folder.
>```cmd
>cd AppData\Local\Android\Sdk\emulator
>```
>![[../images/14/dynamic_activity_dir.png|Navigating to Emulator Directory|700]]
>Using the emulator executable, I list the available AVDs which show the Pixel 3a device I set up in the previous step.  These are the devices I have set up to emulate.
>```cmd
>emulator.exe -list-avds
>```
>![[../images/14/dynamic_activity_avds.png|Listing AVDs Using Emulator Executable|700]]
>To start the AVD, I use the emulator executable with the `-avd` option and the name of the AVD ID listed in the previous command.
>```cmd
>emulator.exe -avd Pixel_3a_API_34
>```
>![[../images/14/dynamic_activity_start_avd.png|Starting AVD Using Emulator|700]]
>After a few moments, my Pixel 3a emulated device pops up and eventually fully loads!  I can interact with it using my mouse simulating taps and drags, much like a real phone.  The emulator has several settings that can be adjusted in the context menu shown on the right of the emulated device.
>![[../images/14/dynamic_activity_avd_init.png|Emulated Pixel 3A Home Screen|250]]
>Now that the emulated device is running, I download the APK to my host computer using the same method as the previous activity.  Next, I open a new terminal session on my Windows host, navigate to the SDK's platform tools directory where ADB is located, and install the application from the host. The first install command failed because the debugger daemon was not initially running, but it shows that it was started, so I re-ran the same command and received a Success message suggesting Modern Portfolio was installed on the emulated device.
>```cmd
>cd .\AppData\Local\Android\Sdk\platform-tools\
>.\adb.exe install --bypass-low-target-sdk-block C:\Users\danie\Downloads\newtonanalytics.modernportfoliotheory_1.1_androidappsapk.co.apk
>```
>![[../images/14/dynamic_activity_install.png|Installing Modern Portfolio On AVD|700]]
>ADB is a powerful tool that can run commands on the device and provide us terminal access to the AVD.  To launch a shell on the emulated device, I run ADB with the shell command that immediately drops me into a new CLI.
>```cmd
>.\adb.exe shell
>```
>![[../images/14/dynamic_activity_adb_shell.png|ADB Shell On Emulated Device|700]]
>Let's verify that the Modern Portfolio application is indeed installed while enumerating any other packages by running the debugger's built-in package manager command.
>```adb
>pm list packages
>```
>![[../images/14/dynamic_activity_list_packages.png|Listing AVD Packages Using ADB Shell|700]]
>About halfway down the list, I see the installed application!
>![[../images/14/dynamic_activity_confirm_install.png|Confirming App Installation|700]]
>Similarly, jumping onto the emulated device GUI and swiping up lists the applications installed, which now includes Modern Portfolio (grey icon)!
>![[../images/14/dynamic_activity_gui_app_confirm.png|AVD GUI Application Install Confirmation|210]]
>Let's see if we can start the application using an intent from the operating system.  I'll target the MainActivity component we observed in the manifest file during static analysis.  While within the ADB shell, I run the activity manager command targeting the package and activity name.
>```adb
>am start -n newtonanalytics.modernportfoliotheory/.MainActivity
>```
>![[../images/14/dynamic_activity_intent.png|Starting MainActivity Using Intents|700]]
>And, jumping to the emulated device, I see that the app was launched!
>![[../images/14/dynamic_activity_launched.png|Launched Modern Portfolio App|210]]
>If I try to launch another activity from ADB, such as the DisplayContact activity, I get a permission denied error which suggests that the permissions on this activity mitigate other applications from launching it!
>```adb
>am start -n newtonanalytics.modernportfoliotheory/.DisplayContact
>```
>![[../images/14/dyanamic_activity_denied.png|Intent Permission Denied|700]]
>In this activity, we established how we can dynamically test an application while using Android Studio's emulator and debugger.  From here we can start testing payloads against some of the vulnerabilities identified during static analysis.  We could also use additional tools to capture and monitor how the application interacts with the network interface of the emulated device.

Developing exploits and proofs of concepts can be somewhat time consuming.  Therefore, some security professionals have developed exploit kits that streamline common exploits of known vulnerability classes.  These tools are typically compiled Android applications that have been configured to target a vulnerability discovered in a victim application.  Compiling the malicious application, installing it, and then running its exploits, quickly demonstrates to application owners the severity of the vulnerabilities discovered.  

They also serve as a great tool for testing vulnerability mitigations as they can provide measurable assurance that a vulnerability has been remediated.  One of my favorite testing frameworks is Drozer by WithSecureLabs.  You can find its source code and use instructions in https://github.com/WithSecureLabs/drozer.  Another great dynamic testing and exploiting tool is PhoneSploit by prbhtkumr that can be downloaded at https://github.com/prbhtkumr/PhoneSploit.

## Summary
This chapter began with the rise of mobile applications and then dove into Android’s core architecture, including its sandboxed processes, Linux-based permission model, and four key components (Activities, Services, Broadcast Receivers, and Content Providers) tied together by Intents and declared in the `AndroidManifest.xml`.  We explored how application resources, storage options (internal, external, and content providers), and network communications must be carefully secured by highlighting modern runtime permission requests, scoped storage, and HTTPS enforcement.  We then examined common mobile attack surfaces, such as command injection, information disclosure, path traversal, local SQL injection, tapjacking, and insecure WebView usage.  The importance of hardening exported components and sanitizing all inputs regardless of source were mitigations discussed in the chapter.  Finally, we outlined a methodology for uncovering these vulnerabilities through static analysis (APK unpacking, Smali decompilation, QARK scans) and dynamic analysis (emulator-based testing with ADB, Drozer, and PhoneSploit) to give practitioners the tools they need to identify and demonstrate security flaws effectively.

>[!terms] Key Terms
>**Activities** - The user-facing screens in an Android application that render the interface, receive inputs, and drive navigation between views.
>
>**Application Resources** - The bundled assets that provide the rich content and UI structure for an app, such as images, audio files, and XML layout files.
>
>**Broadcast Receivers** - A component that registers to receive and handle asynchronous system or application generated broadcasts (intents) without a direct user interface.
>
>**Components** - The four fundamental building blocks of Android apps (Activities, Services, Broadcast Receivers, and Content Providers) that define how apps interact with users, the system, and each other.
>
>**Content Provider** - A component that manages and exposes structured data (SQLite databases or files) via a URI-based interface to other apps under controlled permissions.
>
>**Credential Security** - The practice of safeguarding authentication secrets by using Android’s `AccountManager` or secure storage instead of plaintext storage.
>
>**Data Storage** - The three persistence options available to Android apps (internal storage, external storage, and content providers) with varying isolation and access characteristics.
>
>**Input Validation** - The process of verifying that all incoming data meets expected formats and constraints before processing, to prevent injection and other input-based attacks.
>
>**Intents** - Asynchronous messages that apps and the system use to request actions or launch components, resolving targets by explicit settings or intent filters.
>
>**Manifest File** - The `AndroidManifest.xml` XML document at the root of the APK that declares an app’s components, permissions, SDK requirements, and other metadata.
>
>**Native Security** - The built-in Linux kernel-based protections in Android (ASLR, NX, discretionary file permissions, and IPC enforcement) that isolate apps and processes.
>
>**Network Security** - The requirement that all network communications use encrypted channels (HTTPS via `HttpsURLConnection` or secure sockets) to protect data-in-transit.
>
>**Permissions** - The access controls declared in the manifest, and granted at install or runtime, that enforce the principle of least privilege for app components.
>
>**Services** - Background components without a UI that perform long running operations or expose binding interfaces for other apps and system processes.
>
>**WebView** - An embeddable browser frame within an activity that renders web content, which must be hardened to avoid web-based attacks.
## Exercises
>[!exercise] Exercise 14.1 - Static Analysis
>Static analysis of Android applications starts with acquiring the app file APK.  Unzipping the file and then decompiling/disassembling the application allows for review of the app's source code and settings.  The process of preparing and analyzing the app can be automated using the Qark tool.
>#### Step 1 - Get APK
>After starting the Kali VM in Bridge Adapter network mode, open a browser and navigate to https://androidappsapk.co/.  Search for `newtonanalytics.modernportfoliotheory` and follow the link of the Newton Analytics application.  After pressing the "Download APK" button, you are redirected to the download page.  Press the download icon next to the app to start the download.  Observe that the APK file is downloaded to your download folder.
>
>Alternatively, the APK is available within the textbook's file directory.
>#### Step 2 - Install and Run Qark
>Clone the Github repository qark to your Kali VM.
>```bash
>git clone https://github.com/linkedin/qark 
>```
>Change directory into the qark folder and then set up a python virtual environment.  Observe that the command line now shows (venv).  You will install and run qark from this virtual environment.  You will have to re-enter the environment between reboots to use the tool again.
>```bash
>cd qark
>virtualenv -p python3 venv 
>source venv/bin/activate
>```
>Install the requirements and run the qark setup.  Note that there may be some errors during the installation, which could be okay.
>```bash
>pip install -r requirements.txt 
>sudo python setup.py install
>```
>Run qark while targeting the APK downloaded in the previous step.  Qark will decompile and analyze the APK, then produce a report of findings.  Note that the name of the APK might be slightly different or you may need to `unzip` it.  Once the tool finishes, copy down the path of the report on the last output as you'll need it in a later step.
>```bash
>unzip -d ~/Downloads ~/Downloads/newtonanalytics.modernportfoliotheory*.zip
>sudo qark --apk ~/Downloads/newtonanalytics.modernportfoliotheory*.apk
>```
>#### Step 3 - Manually Analyze the App
>With the app decompiled and analyzed, navigate to the `build/qark` directory and list the outputs.
>```bash
>cd build/quark
>ls -la
>```
>This directory contains the extracted and disassembled `AndroidManifest.xml`, JAR files (source code), and resources.  It also contains some artifacts from tools used to do the extractions/decompiling.   Display the `AndroidManifest.xml` contents using cat and then describe what Android Components you observe.
>```bash
>cat AndroidManifest.xml 
>```
>Navigate to application's source code in the `procyon/newtonanalytics/modernportfoliotheory` or `build/qark/cfr/newtonanaltyics/modernportfoliotheory/` folders and display the `DBHelper.java` file contents.  Look through the disassembled source code and identify where the app could be vulnerable to a SQL injection.  Describe how you would mitigate SQL injection vulnerabilities in Android applications.
>#### Step 4 - Analyze Qark Report
>Open your Kali VM's browser and navigate to the `qark` report file path (`/usr/local/lib/python3.11/dist-packages/qark-4.0.0-py3.11.egg/qark/report/report.html`).
>
>Observe that the simple HTML report has found many "Logging" vulnerabilities.  Browse through the report and identify 2 other unique vulnerability types and:
>1. Describe the vulnerability 
>2. Where the vulnerability exists in code and display its source code 
>3. Describe the severity and impact of the vulnerability 
>4. Describe how to mitigate the vulnerability (may require research).


>[!exercise] Exercise 14.2 - Dynamic Analysis
>This task requires you to use your Host (not a VM) and the instructions assume you are using a Windows PC.  If your host computer is MacOS, you can still use the instructions, but some of the Android Studio paths will be different.  You will install Android Studio/SDK and sideload the "Modern Portfolio" application.  You will then launch the Activity component using the Android debugger utility.
>#### Step 1 - Install Android Studio
>From your Host PC, navigate to [https://developer.android.com/studio](https://developer.android.com/studio) and press the "Download Android Studio" button to download the installer. The file is about 1 GB and will take a couple of minutes to download depending on your internet speed.
>
>1. Once the installer is downloaded, find the file in the Downloads folder and double click on the EXE file to launch the installation.
>2. After accepting any UAC prompts, the Android Studio Setup wizard launches. Press Next to begin the setup.
>3. Ensure that the "Android Studio" and the "Android Virtual Device" components are selected and press Next.
>4. Accept the default Configuration Setting installation location and press Next.
>5. Press Install on the Choose Start Menu Folder to begin the installation.
>6. After a few moments, the installation will be complete. Press the Next button and then Finish with the "Start Android Studio" box checked.
>7. The "Welcome to Android Studio" window should appear unless the SDK didn't install. Use the remaining instructions in this step if the SDK didn't install, otherwise go to the next step.
>#### Step 1.1 - Install SDK (if needed)
>If you are prompted to install the SDK in Android Studio Setup Wizard, press Next to install.
>
>1. Accept the SDK default location and press Next.
>2. Verify the SDK setting and press Next.
>3. Accept the android-sdk-license agreements and press Finish.
>4. After a few moments, the SDK will complete installation. Press Finish.
>5. Once installed, the "Welcome to Android Studio" window will appear.
>#### Step 1.2 - Install Virtual Device (if needed)
>Verify that a virtual device (Pixel 3a API 34) was created during the installation. Within Android Studio, press the "More Actions" dropdown and select Virtual Device Manager.  If a device appears, consider this step complete! Otherwise, select Create Device.
>
>- Scroll down and select "Pixel 3a" and then press Next.
>- Select the "API 34" image download icon to download API level 34 x86_64 Android API 34 target.
>- A download popup window will appear. Accept the License Agreement and press Next. Allow a couple minutes for the ~1GB image to download and then press Finish.
>- Once downloaded press Next in the Virtual Device Configuration window. Finally, press Finish to complete the Android Virtual Device (AVD) setup.
>#### Step 2 - Launch Emulator
>On your Host, launch a command prompt and change directory to the Android SDK emulator folder in your user's AppData folder.
>```bash
>cd AppData\Local\Android\Sdk\emulator
>```
>List the Android Virtual Devices (AVD) using the emulator binary. Note, your emulator might include an extension level, which is fine.
>```bash
>emulator.exe -list-avds
>```
>Start the device using emulator. Make sure to replace the name of the emulator with the output from the previous command.
>```bash
>emulator.exe -avd NAME_OF_AVD
>```
>Observe that the emulator starts the device! Wait a moment for the emulated phone to load.  
>#### Step 3 - Download the APK
>See Exercise 14.1, step 1 if needed.
>#### Step 4 - Launch Activity Through an Intent
>We have already performed static analysis using the `qark` tool. Qark identified that the `AnroidManifest.xml` included an Activity (MainActivity) that did not include explicit intents and/or permissions. This means that any app can call the Modern Portfolio MainActivity through the OS intent system and launch the Activity.
>
>Open another terminal on your host computer and navigate to your user's `AppData\Local\Android\Sdk\platform-tools` directory.
>```bash
> cd .\AppData\Local\Android\Sdk\platform-tools\ 
>```
>Install the APK application using Android debugger. Make sure to update the path and filename to where your APK file was downloaded.
>```bash
>.\adb.exe install --bypass-low-target-sdk-block C:\PATH\APP.apk
>```
>Enter an Android debugger shell that launches a terminal session on the emulated device.
>```bash
>.\adb.exe shell
>```
>List the packages installed on the device while in the `adb` shell. Observe that Modern Portfolio is included in the list (about halfway down).
>```bash
>pm list packages
>```
>Open the apps page on your emulator (swipe up) and observe that Modern Portfolio is installed (grey icon)!  Send an intent from the debugger to evidence open Activity using Android debugger.  Observe that the app is launched in the emulator! 

[^1]:Application fundamentals | Android Developers; Android; April 22nd, 2024; https://developer.android.com/guide/components/fundamentals
[^2]:Uber allegedly used secret program to undermine rival Lyft | Uber | The Guardian; April 27, 2024; https://www.theguardian.com/technology/2017/apr/13/uber-allegedly-used-secret-program-to-cripple-rival-lyft