# Chapter 13 - Cloud Security
![](../images/13/cloud_security.jpg)

Some organizations still maintain data centers and on premise server rooms with racks of network and compute equipment that powers an organization; however, more and more companies are moving to cloud services to support operations and streamline technical staff needed to support information technology.  The past decade has seen more information technology moved to the cloud in an array of services with no end to the upward trend.  This rise in investment has generated many new cloud offerings and services that increases overall productivity.  These services represent abstractions of core computer science topics like compute, networking, and applications.  As such, many of the traditional information security risks still translate into the cloud and new tools, techniques and procedures have been developed to break the security of cloud tenants.  Within this chapter you will learn the fundamentals of cloud technologies and how they are used in organizations.  From there you will discover the ways in which an organization can protect and defend cloud environments and methods used to attack cloud services.

**Objectives**
1. Explain how organization use the cloud and the services they offer.
2. Create and configure an AWS cloud account with users of various permission levels
3. Understand the basic AWS security services and how to harden AWS accounts using CSPM.
4. Distinguish between traditional network and system attacks and methods for attacking cloud services.
## Cloud Overview
Before we begin studying the attacks and countermeasures of the cloud, its important to understand what the cloud is and how organizations use it.  The cloud is a generalized term that can be thought of as "someone else's computer".  Instead of an organization buying, installing, and configuring network and server equipment on racks in a server room or data center, the outsource that effort to a third party.  This enables the business, and its technology specialists, to focus on their competitive advantages and less on the maintenance of physical infrastructure.  The following section will introduce the reader to the cloud models, characteristics of cloud use cases, the types of service models available in the marketplace, and some of the most popular cloud providers.
### Cloud Models
One of the fundamental aspects of the cloud is the idea of *tenancy* or how data and systems are separated between customers of a cloud environment.  Its common for an organization to expect that their systems are not accessible to third parties as most traditional networks enjoy physical separation from other organizations.  Even in a colocation data center, that is shared with many customers, each tenant would be provided a physical cage that is separate from the racks and servers of other tenant cages.  These same principles of separation apply to cloud environments to varying degrees. 

Most organizations that are on the cloud are on a **public cloud model** where all customers share network, compute, and storage resources.  These resources share the same physical space.  For instance a single hypervisor might host virtual machines for different customers.  However, the public cloud model logically separates client tenants using virtualized technologies such as *virtual local area networks (VLAN)*.  This ensures that customer traffic can't reach third party tenants.  But some customers may have significant reservations to sharing resources with other tenants.

Logical separations are not impervious to vulnerabilities that allow escaping or breaking out of logical restrictions.  It is feasible, and not as rare as you might think, that a vulnerability in the underlying host will enable an attacker to move laterally between tenants.  For customers that have a low tolerance for breaches, and who are willing to pay a premium, they can procure a **private cloud** that keeps their data and systems physically separate from other tenants.  As we'll explore in the following section, this allows the customer to enjoy the same benefits of cloud services while have a more strict security posture.

On the opposite side of the cloud model spectrum from private cloud is the **community cloud model** where a single tenant hosts multiple customers.  This was particularly true when the cloud was in its infancy as many network services were shared among all customers.  For example, each customer virtual machine was on the same network as the other!  Another interpretation of a community cloud is one that is shared between partnering customers.  This is common in organizations that form strategic partnerships with each other finding the sharing of resources to be most effective for their operations.

As we will later cover many organization's approach to the cloud is heterogenous and they use many cloud models, services, and vendors.  Under the **hybrid cloud model** a customer might have any mixture of cloud models they use for their operation.  For example, an organization could maintain normal services from a public cloud while offering federal government customers a service from a private cloud.  Organizations choose the cloud for a number of reasons which center around the value proposition and characteristics of the cloud services available.
### Cloud Characteristics
Organizations move to the cloud for a number of reasons but is usually due to the potential of productivity increases and cost optimizations.  Many new firms these days, such as start ups, will build their information technologies in the cloud from the beginning.  This can be explained by several factors, but perhaps one of the most compelling reasons is because of cost.  Cloud offerings are usually priced on use in a "pay as you go" model.  Which means a company with little money that can be spent towards IT infrastructure can get started for little money.  As these companies grow, so does their consumption of cloud services and correspondingly the costs of those services.

>[!info] Information - On-Premise Cash Outlay
>An organization that builds their infrastructure on-premise, that is not in the cloud, must pay for the space, the racks, the network equipment, and the server equipment which can cost several hundreds of thousands of dollars in immediate cash.  This cost does not realize any immediate benefit as no product or service would be deployed yet.  However, any additional changes to software running on this infrastructure won't cost any additional funds.  It is also arguable, and most of the time justifiably so, that in the long run the costs of running on-premise equipment is less expensive then equivalency on the cloud.

On-premise infrastructure procurement includes a requisite, proposal, and plans, all before equipment is purchased and well before it starts producing any value.  Once equipment is finally purchased there is a lead time of days to weeks before the equipment is assembled, shipped, and installed.  This pain point is solved by cloud services as an administrator or engineer has the capability to press a few buttons and setup a wide arrange of infrastructure in a few moments.  The on demand nature of cloud services simplifies and streamlines infrastructure deployment, almost too easily.  Cloud service providers will offer an array of virtual services that meet almost every need that on-premise facilities are able to accomplish.

The providers are able to do this by pooling resources that are shared by all tenants.  Building off of virtualization technology and the idea that most equipment is idle most of the time, cloud providers leverage economies of scale driving down operational costs while maximizing customer experience.  This in turn enables elasticity of the services that can scale alongside the varying demands place on customer infrastructure.  For instance, if a customer's website has a spike in demand, the customer can deploy additional clustered compute instances that expand the capacity of the website.  When the demand spike subsides, the additional compute instances can be terminated all the while the customer is only paying for the resources used and not having to worry about maximizing the value of unused capacity.

Service that cloud providers offer for a price are measured by consumption such as the amount of cores a CPU uses, bytes passing through a network, or gigabytes used on a storage solution.  These measured services enable organizations to better plan their cost structures surrounding information technology including scaling their business while understanding the potential cost of growth.  This section focused primarily on the infrastructure use cases for the cloud, but not all cloud providers focus on the infrastructure side of information technology.  The next section explores the types of cloud providers and business models.
### Service Models
The previous section described how an organization might use the cloud to host their information technology infrastructure.  Really any physical infrastructure has the potential to be hosted by a cloud provider and abstracted through a web console where the customer is able to deploy an entire virtual network.  This type of cloud offering is called **infrastructure as a service (IaaS)** and has become the bedrock of cloud solutions over the last decade.  Cloud administrators create this infrastructure that includes networks, firewalls, routers, servers, databases, and more through a web interface.

>[!info] Information - Infrastructure as Code (IaC)
>It is completely reasonable to deploy cloud infrastructure through a web console; however, there is an opportunity lost by doing so.  Should the administrator ever need to redeploy that potentially complex infrastructure, such as during a disaster recovery scenario, they would have to retrace their exact steps which would be precarious and take some time.  Another issue with deploying infrastructure through the web GUI is that changes are not peered reviewed so mistakes could slip by increasing costs or causing downtime.  These issues are resolved through **infrastructure as code (IaC)** where all cloud infrastructure can be coded and used for deployments.  This is possible as cloud providers use APIs to manage infrastructure, which the GUI uses as well!  IaC can be reviewed and approved in code changes and merges and can be re-ran at any point in the future.  Another benefit is the concept of self documenting, as it can be clear what infrastructure there is and how it is configured by reading the code.

Common patterns emerged for cloud use cases especially for developers.  Web developers, or engineers, love the cloud for the convenience and low up front costs.  However, many developers focus on the applications they develop and want to worry less about the infrastructure it runs on.  **Platform as a service (PaaS)** cloud models sprang into existence to fulfill the need where developers can deploy an application to a pre-configured and deployed infrastructure stack.  PaaS expedites development time to market as less cognitive load is required to build and deploy the underlying infrastructure.

The last service model worth exploring is the most common cloud model by provider count.  Many companies have converted applications from running within on-premise service onto cloud available technology known as **software as a service (SaaS)**.  Usually the conversion of an application from on-premise to SaaS also comes with a change in the pricing model where the former was a license, per server install, and the former is a subscription, such as number of users charged by month.  The benefit to the application provider is that they guarantee a recuring revenue stream in perpetuity by having a SaaS offering; whereas the customer benefits by not having to maintain on-premise equipment for an application. 

Another way to consider cloud models is by how they divide the responsibilities of the technology stack between the cloud provider and the customer.  The following table offers a list of areas to consider responsibility across each model type.  
![[../images/13/responsiblity_matrix.png|Responsibility Matrix|700]]
I've included on-premise to illustrate that such an effort requires the full responsibility of the would be cloud customer.  Moving to the right we see that IaaS providers only maintained the physical hosts whereas the customer would be responsible for their data all the way through to their operating systems.  That would include the installation of OS, licensing compliance, updates, administration, really anything to do with the operating system.  The customer doe not need to worry about the underlying hardware that supports that operating system as the cloud provider would purchase, install, and maintain the CPU, storage, RAM, and networking.  Next is PaaS where the cloud provider takes care of the operating system but the customer brings their own application and is responsible for the data and accounts on the application.  Finally, SaaS solution providers build and maintain their applications and the systems they reside on.  The customer is only responsible for maintain the user access and data within the SaaS offering.

>[!tip] Tip - SOC2 Carve Outs
>Imagine a SaaS provider that uses a third party IaaS and you are the customer of the SaaS application.  As part of SOC2 compliance audits, the chaining of responsibility could be a challenge to audit; therefore, as part of the SOC2 framework, the auditor can rely on the IaaS third party's SOC2 and "carve out" the controls in lieu of that provider already achieving SOC2 compliance.  But the inheritance of these attested controls does not displace any responsibilities the SaaS provider or SaaS customer has in accordance with the responsibility matrix - their SOC2 audits would focus on the areas of their responsibilities.
### Cloud Providers
Some of the most popular cloud service providers have likely already heard of such as Microsoft's Azure, Google's Cloud Platform (GCP), and Amazon's Web Services (AWS).  Each of these providers offer services across the model types IaaS, PaaS, and SaaS.  With any of them, you can create an entire virtual network with servers accessible from anywhere in the world.  These providers also offer platform services for developers to conveniently deploy apps without worrying about the underlying operating system and infrastructure.  They also offer SaaS solutions, especially Microsoft's Office 365 and Google's Workspace (FKA G Suite) that provide browser based applications for email, word processing, spreadsheets and presentations.

These are the three big players in the cloud space that comprise of the majority of the market.  AWS has the largest market and have pioneered cloud services for many years over Microsoft and Google; however each year Microsoft has been gaining in market share.  Microsoft has a competitive advantage in this space as many organizations rely on Windows domains to manage their environments and Microsoft has been building services that align to existing customers.  This is especially true with their Entra services (FKA Azure Active Directory) which offers identity provider services for integrating identity and access management, a wildly popular service.  So popular in fact that many SaaS applications are configured with Azure Entra supporting *single sign on (SSO)* and SAML authentication.

Google Workspace is also very popular as it is a less expensive, and just about as good, alternative to Microsoft's Office.  Many companies use Workspace for their basic application needs which can be served to any device with a browser and shared between members of an organization.  It is very common for organizations to have a *multi cloud network* where users access several cloud providers as depicted below.
![[../images/13/multi_cloud.png|Multi Cloud Network|350]]
Here, a developer may access AWS using Entra to deploy an application and store their technical documentation in Workspace!  Having a firm knowledge of the services from the providers is a marketable skillset.  The next section will explore AWS's infrastructure services and creation of a new cloud account.
## Amazon Web Services
AWS Regions
AWS Services
>[!activity] Activity 13.1 - Create and Setup AWS Account
## Defending the Cloud
Cloud Security
AWS Key Management Service
AWS CloudTrail
AWS GuardDuty
AWS IAM
IAM Policies
Cloud Security Posture Management
>[!activity] Activity 13.2 - ScoutSuite CSPM
## Attacking the Cloud
Initial Access
Credentials
>[!activity] Activity 13.3 - Leaked Credentials

Misconfigurations
>[!activity] Activity 13.3 - S3 Buckets

AWS Privilege Escalation
Pacu

## Exercises

> [!exercise] Exercise 13.1 - Create and Setup AWS Account
> In this task you will create an AWS account, secure the root user, and create an IAM administrator.
> >[!warning] Warning - AWS Costs
> > This activity requires you provide AWS with a credit card for any charges. If you follow the lab instructions carefully you will have little to no charges. However, charges can occur if you setup additional services or leave services running. You are responsible for any financial costs associated with the lab.
> #### Step 1 - Create AWS Account
>
> From your host computer, open a browser and navigate to [https://aws.amazon.com/](https://aws.amazon.com/) . Press the "Create an AWS Account" button in the top right corner. Enter your email address (eg CSUS, personal, etc) for the "Root user email address" and enter your name under the "AWS account name". Press "Verify email address".
> 
> After submitting the first form, you will receive a verification email from AWS with a verification code. Enter the verification code and press "Verify"
> 
> Enter a "Root user password" and confirm the value then continue to the next step. It is important to use a strong password to prevent your account from getting compromised and running up costs that you would be responsible for.
> 
> The next step requires your name, contact, address and use information. Complete the form with accurate data as this is how AWS can contact you if something goes wrong with your account. Select "Personal - for your own projects" for the type of account.
> 
> The next step requires you enter your billing information. You will receive little to no charges under the free tier so long as you follow the lab instructions. I'd recommend using a credit card instead of a debit card to avoid cash being removed directly from your bank account in the event there is a charge. Enter your payment information and press "Verify and Continue".
> 
> The next step requires you confirm your identity. Enter your phone number and complete the CAPTCHA.
> 
> Upon submission you will receive a text message with a numeric code. Enter the numeric code to confirm your identity.  In the final step, select "Basic support -Free" and "Complete sign up"
> #### Step 2 - Setup Root User MFA
> With your AWS account setup, sign in to the management console by pressing the "Sign In to the Console" or "Go to the AWS Management Console" on the page after the initial setup. Otherwise, navigate to [https://aws.amazon.com](https://aws.amazon.com/) and press the "Sign In to the Console" button in the upper right corner. Select "Root user" and enter the email address you used to setup the account. Next enter your password to log in to the console as the root user.
> 
> Now that you are logged in, navigate to the user (root) settings selecting the account drop down menu in the upper right corner and pressing "Security credentials".
> 
> Press "Assign MFA device" in the Multi-factor authentication table.
> 
> Select a "Device name" and choose an MFA device. "Authenticator app" can be of your choosing, some recommended free options are Google or Microsoft Authenticator apps available for free in your phone's application store. If you don't already have one, go to your phone's application store, download and install.
> 
> For this demonstration, we are using Authenticator app. With the authenticator app installed on your phone, press the add account button (or equivalent) and scan QR code option. In the browser MFA setup step, press the "Show QR code". Scan the code and enter the MFA consecutive codes as prescribed in the step's instructions. Then press "Add MFA"
> #### Step 3 - Setup IAM User
> Using the root user for administrative activities is considered a bad practice. You will create a non-root administrator IAM user for all activities in this and other AWS labs.
> 
> Search for "IAM" in the services search bar at the top of the screen and follow the link for the IAM service.
> 
> Select "Users" in the left navigation pane to begin the process of creating a user.
> 
> Press the "Create user" button on the Users page.
> 
> Enter your name as the "User name", check the box "Provide user access to the AWS Management Console" so the user can log into the console. Select the "I want to create an IAM user" option. Enter a strong password and unselect the "Users must create a new password at next sign-in" checkbox. Press the "Next" button.
> 
> Set the IAM user permissions to administrator by selecting the "Attach policies directly" option and marking the "AdministratorAccess" policy checkbox. Then press "Next".
> 
> Review the IAM creation settings and press "Create user".
> 
> After the user is created, observe the "Console sign-in URL" link. This link includes the AWS account number. You should write down the AWS account number and this URL to login to the console. Otherwise, you'll have to log in as the root user to find your account number and then log out to log in as the IAM user later.
> 
> Sign out as the root user by selecting the account dropdown and pressing the "Sign out" button. Note the AWS account number which is needed to login as an IAM user.
> 
> Navigate to the IAM user sign on link provided when you created your IAM user. It should look like [https://060434063276.signin.aws.amazon.com/console](https://060434063276.signin.aws.amazon.com/console) but with different numbers. Alternatively, you can navigate to [https://console.aws.amazon.com/console/home?nc2=h_ct&src=header-signin](https://console.aws.amazon.com/console/home?nc2=h_ct&src=header-signin) select "IAM user", enter your AWS account number, then IAM username and password to login. Either way, enter your IAM (not root) username and password to sign in.
> 
> While logged in as your IAM administrator user (not root), navigate to the IAM service by searching IAM in the search bar (top bar) and selecting the IAM service link.
> 
> Select "Users" in the left navigation menu to observe all IAM users.
> 
> Select the IAM user you created (and are logged in as) to view its settings.
> 
> Select the user "Security credentials" tab. Setup an MFA device following the same procedure as the root MFA device. Consider naming the device something notable in your authenticator app (phone) to distinguish it from the root account.


>[!exercise] Exercise 13.2 - Scout Suite CSPM
>In this task you will create an IAM user with limited permissions and scan your AWS account to detect security misconfigurations. You will then identify and remediate security issues raised by the scanning tool.
>
> >[!warning] Warning - AWS Costs
> > This activity requires you provide AWS with a credit card for any charges. If you follow the lab instructions carefully you will have little to no charges. However, charges can occur if you setup additional services or leave services running. You are responsible for any financial costs associated with the lab.
> 
> #### Step 1 - Create IAM User
> Log into your AWS account using your administrator IAM user (not root). Navigate to the IAM service and the Users page.
> 
> Press the "Create user" button to start the user creation process. Enter "auditor" as the username and leave "Provide user access to the AWS Management Console" unchecked. Then press Next.
> 
> In the next step of the wizard, choose "Attach policies directly". Using the filter "AWS managed - job function", search for and select "ReadOnlyAccess" and "SecurityAudit" permission policies. Press Next and then "Create user".
> 
> Select the created user "auditor" from the Users page.
> 
> Navigate to the "Security credentials" tab and scroll down to the "Access keys" section. Press the "Create access key" button to create a user token that can be used within the command line interface.
> 
> With the create access key wizard launched, choose the "Command Line Interface (CLI)" option and agree to the confirmation. Then press Next and then "Create access key".
> 
> Once the access key is created, press the "Show" link to reveal the secret access key. Copy BOTH the "Access key" and "Secret access key" values to a secure location as they will be needed later in this lab.
> #### Step 2 - Install and Configure AWS CLI
> Launch your Ubuntu VM with Bridge Adapter network mode and open a terminal. Update your system and then install the AWS CLI tool.
> ```bash
> sudo apt update -y
> sudo apt install awscli -y
> ```
> After a couple minutes, the AWS CLI is installed and can be confirmed using the AWS version command.
> ```bash
> aws --version
> ```
> Once the AWS CLI is installed, configure the tool to use the "auditor" IAM credentials created in the previous step. Enter you access key, secret key, region as "us-east-2", and output format as "json"
> ```bash
> aws configure --profile auditor 
> ```
> #### Step 3 - Setup and Run Scout Suite
> Install Python virtual environment.
> ```bash
> sudo apt update -y
> sudo apt install python3-virtualenv -y 
> ```
> You will create a python virtual environment to run Scout Suite from to avoid any Python library conflicts. Create the virtual environment, install scout, and verify its installation. Note that you will have to re-enter the virtual environment to run scout in the future.
> ```bash
> virtualenv -p python3 venv
> source venv/bin/activate
> pip install scoutsuite 
> scout --help 
> ```
> With scout installed, running in a Python virtual environment, AWS CLI installed and configured with the auditor user, run a posture scan to discover any potential security misconfigurations. Scout will make API calls to all AWS services using the auditor account and compare results to a rules engine to identify any potential security flaws. Please allow a few minutes for the scan to complete.
> ```bash
> scout aws --profile auditor
> ```
> Once the scan is complete, an HTML report will be generated and automatically open in the VM's browser.
> #### Step 4 - Analyze and Fix
> Select a vulnerability identified by Scout Suite. Research the vulnerability and document the following: 
> 1. Description of the vulnerable AWS service 
> 2. How is security impacted by the vulnerability/misconfiguration 
> 3. How can the service be fixed (what steps are needed) 
> 
> Next, cure the vulnerability/misconfiguration and re-run Scout to confirm the issue no longer exists in the report. Please keep in mind that some fixes may incur a cost and you should: 
> - Research the service/solution and confirm if a cost will incur; AND 
> - Select a different service/vulnerability to fix to avoid the cost; OR 
> - Fix the service, run the scan, and then remove the fix to avoid/minimize the cost; OR 
> - Incur the cost.

