# Mobile Application Security
![](../images/14/android_armor.jpg)

Prior to artificial intelligence, blockchain or web 3.0, and cloud technologies trends there was the mobile applications fad.  For many years it seemed that every organization was rushing to develop and offer a mobile application to their users.  During this surge of enthusiasm many applications were developed which exposed security risks and new attack vectors against organization systems.  While the hype eventually died down, to make way for the new new thing, mobile applications persisted as a useful mechanism to connect individuals to existing and new organizations.  New organizations leverage the mobile ecosystem to launch businesses solely dependent on its smart phone and table users.  Today, Apple and Android are the major systems that support mobile application development comprising of the extreme majority of the market share.  While both companies approach mobile applications differently, we will focus on the Android system in this chapter due to its relative ease to analyze.  Apple's walled garden architecture makes it more challenging to analyze mobile applications usually requiring a MacOS - which not everyone may have access to.  This chapter will describe the Android system and application basics and then walk the reader through the attacks and counter measures related to Android mobile applications.

**Objectives**
1. Describe Android application fundamentals and operating components.
2. Understand the security features and risks of Android applications.
3. Conduct basic static and dynamic analysis of Android applications using Qark and Android Studio.
## Android Application Basics
Having a basic understanding of how Android applications are developed and operate is important before discussing their security.  At their core, application developers can chose to develop them using Java's Kotlin or C++ languages.  Source code is then compiled using the Android software development kit (SDK) into an Android package file with the extension `.apk`.[^1]  This portable file contains all the data, resources, and source code to run an application on an Android operating system.  They are digitally signed using a developer maintained certificate before being uploaded to Google Play using a developer account.  Once in the store, they can be downloaded and installed by any internet user.

APKs are effectively archive files that can be installed manually onto a device, known as *side loading*, without the use of the Google Play app.  The benefit of installing an app from Google Play is that it must meet Googles privacy and security requirements; although there are plenty of malicious apps that are published at any given time.  It is inadvisable to install Android apps from third party stores or installing manually through side loading, unless the user has taken precautions or otherwise trusts the application source.

Applications running on an Android system, such as a smart phone or tablet, are ran within a segregated process called a *security sandbox*.  This separation from other applications and core features of the operating system helps to minimize the impact a malicious application could have on a device.  We will explore how a misbehaving application takes advantage of Android components to exploit vulnerabilities in other applications later in this chapter.  The application is assigned a unique Linux user that only has access to that application's files using the operating system's discretionary access control policies set by the system.  When the application is launched it is given its own process and runs in isolation from other applications running the environment.

Each app running in a sandbox is also granted least privileges by default.  Application developers have the ability to loosen permission controls on their application to allow various sources to interact with its components.  If mishandled, these less restrictive permissions could open the application up to security vulnerabilities.  Applications can also used other operating system drivers to utilize hardware components, such as contact lists or the camera.  Android ensures these permissions are explicitly granted by the user when installing the app.  You may have seen this as a pop up message during app installations giving you the ability to allow or deny application permissions.
![[../images/14/app_runtime.png|Android Application Runtime Environment|500]]
The graphic above attempts to illustrate some of the previous points.  There are three applications titled A, B, and C (light blue boxes) running within sandboxes on top of the operating system (bottom grey bar).  The operating system maintains each of the application's permissions describing what the application is allowed to access.  In this table, on the bottom left of the graphic, App C has permissions to the camera which is also depicted using a camera icon within the app on the right.  The operating system also maintains databases, such as SQLite, the file system, application users and manages the running applications as processes.  As we will learn in the following section, each application has components that can be invoked using *intents*.  These components access are managed by each application and setup during development.  They restrict an application's ability to interact with other application as shown between App A and App B's blocked arrow.  But they can also enable applications to interact with each other as shown between App B and App C with the green arrows traversing through the intents system.
### Components of Android Applications
Interacting with an application can be performed through its **components** which act like services engaged by the user or other events such as from other applications or the operating system.  While every app can use the components, not every app is built with each of the capabilities the components provide.  Developers chose which components are needed based on the functionality of the app as well as their configurations, such as permissions.  Having a basic understanding of each of the four components is important from the security perspective as they are part of the application's overall attack service because they provide a means to interface with the application.

The **activities** component is the most recognizable component for an Android application because it serves as the user interface.  Any application you have used has a rendering on the screen which presents data and objects like buttons and fields.  This screen, or view, is an activity component which receives inputs such as touches or clicks that trigger logic in the application.  Activities can even be triggered by other applications assuming the activities permissions are set to allow so.  The system interacts with the application through activities while tracking what is on the screen, the processes that start and stop activities, handling of process state, and implementing the user flows between activities as each view transitions to the next.  You can almost think of an app like a web site where each page on that site is the equivalent of an activity.

Many applications allow for features to run in the background while you use another application.  A common example of this is listening to a music app (in the background) while you have another application in focus such as a navigation or maps application.  Applications handle this through the **services** component supporting login running operations and remote processes.  Services don't have any direct user interface but can be classified as a *started service* or a *bound service*.  Started services will terminate when the background process is complete while a bound service remains open for another application or the system to use the service.  Bound services are akin to an open port and service waiting for a connection to begin processing a request.

>[!info] Info - Android Fundamentals Documentation
>Android maintains excellent documentation covered throughout this chapter.  Interested readers are encouraged to read the full documentation on https://developer.android.com/guide/components/fundamentals .

Utilizing the `JobService` and `JobScheduler` for event handling, the **broadcast receivers** component handles the reception of events sent from the operating system outside the regular user flow.  Therefore, this component again does not have a direct user interface but is triggered through announcements made through the system via *intents* which will be covered later.  A classic example of this is the notification of low battery which is derived from system monitoring and sent to all applications.  An application may require a certain level of battery consumption and if the device is low on battery may need to handle the event gracefully.  When the system broadcasts the message, the application's broadcast receiver ingests the event and processes it however it was programmed to do so.

The last component to know about is the **content provider** which handles interaction with content on the device.  This content is a shared set of application data typically stored in the devices file system or internal SQLite database.  Content providers also handle remote web based content and persistent storage locations dedicated to the application's sandbox environment.  Applications with explicit, or implicit, permissions can query or modify data stored within the content provider.  A great example of a content provider is the a phone's contacts as many applications request or require access to this dataset - often for questionable purposes!  Content provider data location is managed using a URI namespace that are also used to manage permissions to the data.  Apps map data to URI namespaces providing other principals or applications access.

I have mentioned the term **intents** a few times in this chapter already but to understand it required the background understanding of components.  Intents are used by the system to activate components and can be though of as the way the system sends inputs to the application.  When a user presses the next button in an activity while using an application, the system interprets the action and sends the app an intent for the next activity - also called user flow.   Similarly, any application can start another application's component, assuming permissions allow it, through intents from the system.  Intents are asynchronous messages used for activates, services, and broadcast receivers.

>[!warning] Warning - Implicit Intents
>Implicit intents can be called by any application and are dangerous as it allows arbitrary applications on a device to hijack a the process flow of a victim application!

When developing an application engineers must design the components and permissions they plan to need.  All the components, and their permissions structure, among other information are configured within the **manifest file**.  This XML document provides information such as the minimum SDK version needed to run the application as well as the version of the application.  The file itself is named `AndroidManifest.xml` and is a great resource to understand basic functionality and attack surface of a subject application.  The file is located at the root of the application's directory and is commonly extracted while reverse engineering an application to study how it works.  We will extract a manifest file in a later activity and review its contents which will look similar to the image below.

![[../images/14/manifest.png|Android Application Manifest File|500]]
The last major item to understand before we start exploring Android security is the **application resources**.  You can think of the app's resources as all the rich content brought into the application such as images, audio files, and formatted layouts prepared in XML format.  Sometimes, malicious application might attempt to hide payloads in resources as an obscure place a malware analyst might not think to look!

>[!activity] Activity 14.1 - Mobile App Risk Assessment
>Individually, or in a small group, analyze what you now understand about mobile applications and determine their:
>- attack surface
>- impact of exploitations
>- mitigations 
## Defending Android Applications
Android has many built in security measures and capabilities within the operating system.  Developers are expected to understand and use these features to protect their applications and data.  By carefully configuring the application to leverage such utilities ensures that the application's attack surface is minimized and reduces the impact of attacks.  This chapter has already mentioned some of these security measures such as permissions and sandboxes but it is worth exploring them in further detail.  The goal of this section is to further define each security item and some of their common pitfalls.  It can be easy to misconfigure an application to be vulnerable so having a strong understanding of the available options promotes good application security hygiene.

>[!info] Info - Android Security Guidelines
>Most of the following topics were derived or inspired by Android's published Security Guidelines.  Their awesome documentation is worth a read!  https://developer.android.com/privacy-and-security/security-tips

There are several **native security** measures in place to protect applications and the overall system.  Because Android is based on a version of the Linux kernel, it inherits many of the security functionality of that operating system.  This includes memory management protections that we explored in the Operating System Security chapter such as ASLR and NX as well as error protections.  Also discussed in that chapter which applies to Android is the file system permissions systems to control access to files on the system.  Android extends permissions by creating a defined user for each application that is constrained to only access that application's files and folders while also running in a sandbox that is segregated from other processes running on the device.  The system provides not only this permission structure but also includes application frameworks for cryptographical operations and an *interprocess communication (IPC)* which is native to the environment.

Applications may interact with remote and local **data storage** in a secure way that prevents unauthorized access.  There is an underlying concern that protected data could be accessed by other apps but Android offers ways to mitigate this risk.  The three storage mediums to consider are internal storage, external storage, and content providers.  *Internal storage* is that storage native to the device - usually flash media that is soldered onto the main board.  By default, internal storage is protected but can be overridden using the `MODE_WOLRD_WRITABLE` and `MODE_WOLRD_READABLE` permission flags.  These flags open the data to be read or written by any application on the device and should be used with caution.  

>[!warning] Warning - Storage Scope Creep
>Sometimes it is the intent to make the application's data available for other applications because the data is benign; however, through the expansion and development of an application that storage could be used to house more sensitive data in the future while forgetting that the permissions allow for world readable.  I have seen applications that misused public storage like this to be used as an input into the application introducing injection flaws.  Be very cautious of such storage use scope creep!

*External storage* that is added to a device, such as through insertion of a micro SD card, is always world readable and writable.  Trusting data on this storage medium that is to be used by the application is precarious given its open nature to the rest of the system's applications.  The last data storage type, *content providers*, was explored in the previous section, include media like the file system and SQLite database.  The content provider access configuration for the application can be configured using the `android:exported` flag where setting to false prevents other applications from reading its data.  Intents to the content providers can be controlled at a more granular level using the `android:grantUriPermissions` setting where the URI is a defined path which enables a developer to allow some access to files while denying access to others.  When using a SQLite database content provider, developers should make use of native SQL functions `query()`, `update()`, and `delete()` as they are parameterized methods which prevent SQL injection vulnerabilities.

>[!tip] Tip - Raw SQL Concerns
>Raw SQL queries written into source code should be heavily scrutinized if not fully avoided.  Technically a raw SQL command accomplishes a task, but if inputs or parameters used within the query, through concatenation, are not treated it could expose a SQL injection vulnerability!

Using **permissions** throughout the components of the application are important to minimize information disclosure risks.  Failure to follow the principle of least privilege in permission settings could result in exposure of data through IPC requests that would otherwise have been protected.  Most of these permission settings can be found set within the component blocks in the manifest file of the application, making it a crucial file for inspecting the security posture of an application.

Applications commonly use HTTP to make requests to internal and external resources.  HTTP is a versatile and useful protocol that most web technologies are built on so it makes sense that a mobile application would rely on it.  However, HTTP is insecure by default as its data is exposed in plaintext and can even be modified while in transit.  **Network security** becomes an important factor when securing Android applications and professionals should require all network connections, such as HTTP, be made over encrypted channels.  The `HttpsURLConnection` and function should be used over HTTP and `SSLSockets` used to wrap other protocols and communications.  It is possible to make network calls using `localhost` but should be avoided in favor of using IPC given its security features within the operating system.  Applications should distrust any data or files downloaded using HTTP or through SMS as they are not encrypted.

Mobile applications are subject to many of the same types of input attacks as web applications are that we reviewed in the Web Application Attacks chapter.  Applications expect inputs from untrusted sources like users and events from other applications and broadcasts.  You may recall that many of these attacks can be mitigated at the source through proper **input validation** where data is checked to meet expected criteria before being logically processed.  

>[!warning] Warning - Trusting Untrusted Input
>It can be challenging for developers to determine the trustworthiness of inputs coming from sources.  Many developers will inherently trust data coming from the operating system or controlled data sources that are adjacent to their project.  These sources may even be part of the overall application; however, second order attacks through such sources are common and difficult to spot.  Therefore, always validate inputs regardless if they come directly from a user or not.

When mobile applications started gaining in popularity many organizations needed to make a strategic decision in their development effort.  Mobile devices have internet browser applications, such as Chrome, that can be used to navigate web pages.  Often these web sites were designed with the expectation of being viewed on a monitor and not a small device like a smart phone.  In response organizations began adapting their web sites using *responsive design* techniques through cascading style sheets (CSS) rendering views depending on the size of the screen being used.  Moreso many organizations have complex dynamic web applications that they did not want to re-create for a mobile site, so responsive design solved these small screen issues.  Market pressures still compelled organizations to develop and deploy mobile applications to meet their users on the devices they were growing accustom to.  

To avoid having to re-write an entire application, many organizations leveraged their existing mobile friendly web applications into the **WebView** feature of Android.  The WebView is a frame within a web application's activity or view that will render a website.  This trick streamlined the adoption of mobile applications for many organizations.  The user experience is typically good and the user often doesn't realize they are looking at an embedded website inside a mobile application!  The heavy use of WebViews exposes a mobile application to the same risks browsers and websites have in addition to the security risks a mobile application already has.  These include the consumption and execution of JavaScript and client side attacks.  Ideally, WebViews have JavaScript disabled to avoid issues like cross site scripting attacks.

**Credential security** is another factor to contemplate with mobile applications. You may have logged into a mobile application using credentials.  Chances are that the form you entered these credentials into was actually a WebView to avoid having to have a mobile application directly process sensitive credentials.  But it could have also been the less common case that the application directly accepted, stores, and processes the authentication of the application.  If an application's design relies on local authentication, versus through a WebView, it is important it leverages the native `AccountManager` feature of Android which acts like a credential vault.  Never store the credentials as plaintext in a content provider to avoid the potential impact of another applications gaining access to them.

>[!warning] Warning - Dynamically Loaded Code
>Updating applications through the Play Store can be a chore and some developers might have the idea to avoid having to submit version changes through the application store altogether by dynamically referencing source code from a remote location.  This practice is very dangerous as it provides an opportunity for a stealthy side channel attack.  Such a setup could go wrong many ways and cause the application to be fully compromised.  The attacker could gain control over the remote resource or could trick the application into accepting an update from another resource.  Using the Play Store provides some level of protection against this and dynamically loaded code should be consider insecure.
## Attacking Android Applications

### Means of Attacks
Vulnerable APIs
![[../images/14/vuln_api.png|Attacking Application HTTP APIs|450]]
Malicious Application
![[../images/14/mal_app.png|Malicious Android Application Interactions|500]]
### Components Attack Surface
- Activities
- Broadcasts
- Services
- Receivers
### Application Attack Types
- Command Injection
- Information Disclosure
- Path traversal
- SQLi
- Tapjacking
### Enumerating Applications
Methodologies
- Static Analysis
- Dynamic Analysis

Tools

>[!story] Story - Newton Analytics - Modern Portfolio Theory

>[!activity] Activity 14.2 - Static Analysis

>[!activity] Activity 14.3 - Dynamic Analysis

## Exercises
>[!exercise] Exercise 14.1 - Static Analysis
>Static analysis of Android applications starts with acquiring the app file APK.  Unzipping the file and then decompiling/disassembling the application allows for review of the app's source code and settings.  The process of preparing and analyzing the app can be automated using the Qark tool.
>#### Step 1 - Get APK
>In your Kali VM using Bridge Adapter network mode, open a browser and navigate to [https://apkcombo.com/](https://apkcombo.com/) . Search for the app "Modern Portfolio" and follow the link of the app made by Newton Analytics.  On the app page, press the "Download APK" button making sure to avoid any ads.
>
>After pressing the "Download APK" button, you are redirected to the download page.  Press the download icon next to the app to start the download.  Observe the APK file is downloaded to your download folder
>#### Step 2 - Install and Run Qark
>Clone the Github repository qark to your Kali VM.
>```bash
>git clone https://github.com/linkedin/qark 
>```
>Change directory into the qark folder and then set up a python virtual environment.  Observe the command line now shows (venv).  We will install and run qark from this virtual environment.  You will have to re-enter the environment between reboots to use the tool again.
>```bash
>cd qark
>virtualenv -p python3 venv 
>source venv/bin/activate
>```
>Install the requirements and run the qark setup.  Note that there may be some errors during the installation which could be okay.
>```bash
>sudo pip install -r requirements.txt 
>sudo python setup.py install
>```
>Run qark while targeting the APK downloaded in the previous step.  Qark will decompile and analyze the APK then produce a report of findings.  Note that the name of the APK might be slightly different.  Once the tool finishes, copy down the path of the report on the last output as you'll need it in a later step.
>```bash
>sudo qark --apk ~/Downloads/newtonanalytics-modernportfoliotheory*.apk
>```
>#### Step 3 - Manually Analyze the App
>With the app decompiled and analyzed, navigate to the build/qark directory and list the outputs.
>```bash
>cd build/quark
>ls -la
>```
>This directory contains the extracted and disassembled AndroidManifest.xml, JAR files (source code), and resources.  It also contains some artifacts from tools used to do the extractions/decompiling.   Display the AndroidManifest.xml contents using cat and then describe what Android Components you observe.
>```bash
>cat AndroidManifest.xml 
>```
>Navigate to application's source code in the procyon/newtonanalytics/modernportfoliotheory folder and display the DBHelper.java file contents.  Look through the disassembled source code and identify where the app could be vulnerable to a SQL injection.  Describe how you would mitigate SQL injection vulnerabilities in Android applications.
>#### Step 4 - Analyze Qark Report
>Open your Kali VM's browser and navigate to the qark report file path ("/usr/local/lib/python3.11/dist-packages/qark-4.0.0-py3.11.egg/qark/report/report.html").
>
>Observe the simple html report has found many "Logging" vulnerabilities.  Browse through the report and identify 2 other unique vulnerability types and:
>1. Describe the vulnerability 
>2. Where the vulnerability exists in code and display its source code 
>3. Describe the severity and impact of the vulnerability 
>4. Describe how to mitigate the vulnerability (may require research).

>[!exercise] Exercise 14.2 - Dynamic Analysis
>This task requires you to use your Host (not a VM) and the instructions assume you are using a Windows PC.  If your host computer is MacOS, you can still use the instructions, however some of the Android Studio paths will be different.  You will install Android Studio/SDK and sideload the "Modern Portfolio" application.  You will then enter exploit the vulnerable Activity component using the Android debugger utility.
>#### Step 1 - Install Android Studio
>From your Host PC, navigate to [https://developer.android.com/studio](https://developer.android.com/studio) and press the "Download Android Studio" button to download the installer. The file is about 1 GB and will take a couple minutes to download depending on your internet speed.
>
>1. Once the installer is downloaded, find the file in the Downloads folder and double click on the EXE file to launch the installation.
>2. After accepting any UAC prompts, the Android Studio Setup wizard launches. Press Next to begin the setup.
>3. Ensure the "Android Studio" and the "Android Virtual Device" components are selected and press Next.
>4. Accept the default Configuration Setting installation location and press Next.
>5. Press Install on the Choose Start Menu Folder to begin the installation.
>6. After a few moments the installation will be complete. Press the Next button and then Finish with the "Start Android Studio" box checked.
>7. The "Welcome to Android Studio" window should appear unless the SDK didn't install. Use the remaining instructions in this step if the SDK didn't install; otherwise go to the next step.
>#### Step 1.1 - Install SDK (if needed)
>If you are prompted to install the SDK in Android Studio Setup Wizard, press Next to install.
>
>1. Accept the SDK default location and press Next.
>2. Verify the SDK setting and press Next.
>3. Accept the android-sdk-license agreements and press Finish.
>4. After a few moments the SDK will complete installation. Press Finish.
>5. Once installed the "Welcome to Android Studio" window will appear.
>#### Step 1.2 - Install Virtual Device (if needed)
>Make sure a virtual device (Pixel 3a API 34) was created during the installation. Within Android Studio, press the "More Actions" dropdown and select Virtual Device Manager.  If a device appears, consider this step complete! Otherwise, select Create Device.
>1. Scroll down and select "Pixel 3a" and then press Next.
>2. Select the "API 34" image download icon to download API level 34 x86_64 Android API 34 target.
>3. A download popup window will appear. Accept the License Agreement and press Next. Allow a couple minutes for the ~1GB image to download and then press Finish.
>4. Once downloaded press Next in the Virtual Device Configuration window. Finally, press Finish to complete the Android Virtual Device (AVD) setup.
>#### Step 2 - Launch Emulator
>On your Host, launch a command prompt and change directory to the Android SDK emulator folder in your user's AppData folder.
>```bash
>cd AppData\Local\Android\Sdk\emulator
>```
>List the Android Virtual Devices (AVD) using the emulator binary. Note, your emulator might include and extension level, which is fine.
>```bash
>emulator.exe -list-avds
>```
>Start the device using emulator. Make sure to replace the name of the emulator with the output from the previous command.
>```bash
>emulator.exe -avd NAME_OF_AVD
>```
>Observe the emulator starts the device! Wait a moment for the emulated phone to load.  The emulated phone can be used like a physical device but using the mouse and keyboard.
>#### Step 3 - Download the APK
>See Exercise 14.2, step 1 if needed.
>#### Step 4 - Exploit Vulnerable Intent
>We've already performed static analysis using the qark tool. Qark identified that the AnroidManifest.xml included an Activity (MainActivity) that did not include explicit intents and/or permissions. This means that any app can call the Modern Portfolio MainActivity through the OS intent system and launch the Activity.
>
>Open another terminal on your host computer and navigate to your user's AppData\Local\Android\Sdk\platform-tools directory.
>```bash
> cd .\AppData\Local\Android\Sdk\platform-tools\ 
>```
>Install the APK application using Android debugger. Make user to update the path and filename to where you APK file was downloaded to.
>```bash
>.\adb.exe install --bypass-low-target-sdk-block C:\PATH\APP.apk
>```
>Enter an Android debugger shell which gives us a terminal session on the emulated device.
>```bash
>.\adb.exe shell
>```
>List the packages installed on the device while in the adb shell. Observe Modern Portfolio is included in the list (about halfway down).
>```bash
>pm list packages
>```
>Open the apps page on your emulator (swipe up) and observe Modern Portfolio is installed (grey icon)!
>
>Send an intent from the debugger to evidence open Activity using Android debugger.
>
>Observe that the app is launched in the emulator! Because this is the first time the app has been launched, we are prompted with a permissions request.

[^1]:Application fundamentals | Android Developers; Android; April 22nd, 2024; https://developer.android.com/guide/components/fundamentals