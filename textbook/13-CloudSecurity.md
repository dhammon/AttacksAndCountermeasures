# Chapter 13 - Cloud Security
![](../images/13/cloud_security.jpg)

Some organizations maintain data centers and on premise server rooms with racks of network and compute equipment that powers their organization; however, more and more companies are moving to cloud services to support operations and streamline technical staff needed to run information technology.  The past decade has seen increasing amounts of information technology moved to the cloud in an array of services.  This rise in cloud investment has generated many new cloud offerings and services that could increase productivity for organizations.  These services represent abstractions of core technology topics like compute, networking, and applications.  As such, many of the traditional information security risks still translate into the cloud while new tools, techniques and procedures have been developed to break the security of cloud tenants.  Within this chapter you will learn the fundamentals of cloud technologies and how they are used by organizations.  From there, you will discover the ways in which an organization can protect and defend cloud environments from the methods used by attackers.

**Objectives**
1. Explain how organizations use the cloud and the services they offer.
2. Create and configure an AWS cloud account with users of various permission levels
3. Understand the basic AWS security services and how to harden AWS accounts using CSPM.
4. Distinguish between traditional network and system attacks and methods for attacking cloud services.
## Cloud Overview
Before we begin studying the attacks and countermeasures of the cloud, its important to understand what the cloud is and how organizations use it.  The cloud is a generalized term that can be thought of as "someone else's computer."  Instead of an organization buying, installing, and configuring network and server equipment on racks in a server room or data center, they outsource that effort to a third party cloud provider.  This enables the business, and its technology specialists, to focus on their competitive advantages and less on the maintenance of physical infrastructure.  The following section will introduce the reader to the cloud models, characteristics of cloud use cases, the types of service models available in the marketplace, and some of the most popular cloud providers.
### Cloud Models
One of the fundamental aspects of the cloud is the idea of *tenancy* or how data and systems are separated between customers of a cloud environment.  Its common for an organization to expect that their systems are not accessible by unauthorized third parties as traditional on-premise networks naturally enforce physical separation from untrusted sources.  Even in a colocation data center, that is shared with many customers, each tenant would be provided a physical cage that is separate from the racks and servers of other tenant cages.  These same principles of separation apply to cloud environments to through private and public cloud models. 

Most organizations that are on the cloud are on a **public cloud model** where all customers share underlying network, compute, and storage resources.  These resources share the same physical servers but are logically/pragmatically separated.  For instance, a single hypervisor might host virtual machines for different customers.  However, the public cloud model logically separates client tenants using virtualized technologies such as *virtual local area networks (VLAN)*.  This ensures that customer traffic can't reach third party tenants.  But some customers may have significant reservations to sharing resources with other tenants as a misconfiguration or undisclosed vulnerability could expose them to attack.

Logical separations are not impervious to vulnerabilities that allow escaping or breaking out of software level restrictions.  It is feasible, and not as rare as you might think, that a vulnerability in the underlying host will enable an attacker to move laterally between tenants.  For customers that have a low tolerance for breaches, and who are willing to pay a premium, they can procure a **private cloud** that keeps their data and systems physically separate from other tenants.  As we'll explore in the following section, this allows the customer to enjoy the same benefits of cloud services while have a more strict security posture.

On the opposite side of the cloud model spectrum is the **community cloud model** where a single tenant hosts multiple customers.  This was particularly true when the cloud was in its infancy as many network services were shared among all customers.  For example, each customer's virtual machine was on the same network as other customers!  Another interpretation of a community cloud is one that is shared between partnering customers.  This is common in organizations that form strategic partnerships with each other finding the sharing of resources that are found to be most effective for their operations.

As we will cover in more detail later, many organization's approach to the cloud is heterogenous and they use a mixture of cloud models, services, and vendors.  Under the **hybrid cloud model** a customer might have any mixture of cloud models they use for their operation.  For example, an organization could maintain normal services from a public cloud while offering federal government customers a service from a private cloud.  Organizations choose cloud services based on a number of factors which usually center around the value proposition and characteristics of the cloud services available.
### Cloud Characteristics
Organizations move to the cloud for a number of reasons but often due to the potential of productivity increases and cost optimizations.  Many new firms these days, such as start ups, will build their technologies in the cloud from the start.  This can be explained by several factors, but perhaps one of the most compelling reasons is because of cost.  Cloud offerings are often priced based on use in a "pay as you go" model.  This means that a company with few resources can get started without having to spend capital on data centers, racks, and hardware.  As these companies grow, so does their consumption of cloud services and correspondingly the costs of those services.

>[!info] Information - On-Premise Cash Outlay
>An organization that builds their infrastructure on-premise, that is not in the cloud, must pay for the space, racks, network equipment, and server equipment which can immediately cost several hundreds of thousands.  Worst yet, this cost does not realize any immediate benefit as no product or service would be developed yet.  However, any additional changes to software running on this infrastructure won't cost additional funds.  It is also arguable that the costs of running on-premise equipment is less expensive then the equivalency on the cloud under a long enough time horizon.

On-premise infrastructure procurement includes a requisite, proposal, and plans, all before equipment is purchased and well before it starts producing any value.  Once equipment is finally purchased, there is a lead time of days to weeks before the equipment is assembled, shipped, and installed.  This pain point is solved by cloud services as an administrator or engineer has the capability to press a few buttons and setup a wide range of infrastructure in just a few minutes.  The on demand nature of cloud services simplifies and streamlines infrastructure deployment, almost too easily.  Cloud service providers will offer an assortment of virtual services that meet almost every need that on-premise facilities are able to accomplish.

The providers are able to do this by pooling resources that are shared by all tenants.  Building off of virtualization technology and the idea that most equipment is idle most of the time, cloud providers leverage economies of scale driving down operational costs while maximizing customer experience.  This in turn enables elasticity of the services that can scale alongside the varying demands placed on customer infrastructure.  For instance, if a customer's website has a spike in demand, the customer can deploy additional clustered compute instances that expand the capacity of the website.  When the demand spike subsides, the additional compute instances can be terminated all the while the customer is only paying for the resources used and not having to worry about maximizing the value of unused capacity.

The services cloud providers offer are priced by measuring the consumption of the service, such as the amount of cores a CPU uses, bytes passing through a network, or gigabytes used on a storage solution.  These measured services enable organizations to better plan their cost structures surrounding information technology including scaling their business while understanding the potential cost of growth.  This section focused primarily on the infrastructure use cases for the cloud, but not all cloud providers focus on the infrastructure side of information technology.  The next section explores the types of cloud providers and business models.
### Service Models
The previous section described how an organization might use the cloud to host their information technology infrastructure.  Really any physical infrastructure has the potential to be hosted by a cloud provider and abstracted through a web console where the customer is able to deploy an entire virtual network.  This type of cloud offering is called **infrastructure as a service (IaaS)** and has become the bedrock of cloud solutions over the last decade.  Cloud administrators create this infrastructure that includes networks, firewalls, routers, servers, databases, and more through a web interface.

>[!info] Information - Infrastructure as Code (IaC)
>It is completely reasonable to deploy cloud infrastructure through a web console; however, there is an opportunity lost by doing so.  Should the administrator ever need to redeploy that potentially complex infrastructure, such as during a disaster recovery scenario, they would have to retrace their exact steps which would be precarious and take some time.  Another issue with deploying infrastructure through the web GUI is that changes are not peer reviewed so mistakes could slip by increasing costs, eroding security, or causing downtime.  These issues are resolved through **infrastructure as code (IaC)** where all cloud infrastructure is coded and used for deployments.  This is possible as cloud providers use APIs to manage infrastructure, which the GUI uses as well!  IaC can be reviewed and approved in code changes and merges and can be re-run at any point in the future.  Another benefit is the concept of self documenting, as it can be clear what infrastructure there is and how it is configured by reading the code.

Common patterns emerged for cloud use cases especially for developers.  Web developers, or engineers, love the cloud for the convenience and low up front costs.  However, many developers focus on the applications they develop and want to worry less about the infrastructure it runs on.  **Platform as a service (PaaS)** cloud models sprang into existence to fulfill the need where developers can deploy an application to a pre-configured and deployed infrastructure stack.  PaaS expedites development time to market as less cognitive load for developers is required to build and deploy the underlying infrastructure.

The last service model worth exploring is the most common cloud model by provider count.  Many companies have converted applications from running within on-premise services into cloud available technology known as **software as a service (SaaS)**.  Usually the conversion of an application from on-premise to SaaS also comes with a change in the pricing model where the former was a license, per server install, and the former is a subscription, such as number of users charged by month.  The benefit to the application provider is that they guarantee a reoccurring revenue stream in perpetuity by having a SaaS offering while the customer benefits by not having to maintain on-premise equipment for an application. 

Another way to consider cloud models is by how they divide the responsibilities of the technology stack between the cloud provider and the customer.  The following table offers a list of areas to consider responsibility across each model type.  

![[../images/13/responsiblity_matrix.png|Cloud Responsibility Matrix|700]]

I've included on-premise to illustrate the effort and responsibility otherwise required.  Moving to the right we see that IaaS providers only maintained the physical hosts whereas the customer would be responsible for their data all the way through to their operating systems.  That would include the installation of OS, licensing compliance, updates, administration, really anything to do with the operating system.  The customer does not need to worry about the underlying hardware that supports that operating system as the cloud provider would purchase, install, and maintain the CPU, storage, RAM, and internet networking.  Next is PaaS where the cloud provider takes care of the operating system but the customer brings their own application and is responsible for the data and accounts on the application.  Finally, SaaS solution providers build and maintain their applications and the systems they reside on.  The customer is only responsible for maintain the user access and data within the SaaS offering.

>[!tip] Tip - SOC2 Carve Outs
>Imagine a SaaS provider that uses a third party IaaS and you are the customer of the SaaS application.  As part of SOC2 compliance audits, the chaining of responsibility could be a challenge to audit; therefore, as part of the SOC2 framework, the auditor can rely on the IaaS third party's SOC2 and "carve out" the controls in lieu of that provider already achieving SOC2 compliance.  But the inheritance of these attested controls does not displace any responsibilities the SaaS provider or SaaS customer has in accordance with the responsibility matrix.  Therefore, their SOC2 audits would focus on the areas of their responsibilities of the service they are providing.  This is an important distinction as I have often heard the false argument from management that a vendor does not need a SOC2 because they are on the cloud and the cloud provider has a SOC2.
### Cloud Providers
You have likely already heard of some of the most popular cloud service providers such as Microsoft's Azure, Google's Cloud Platform (GCP), and Amazon's Web Services (AWS).  Each of these providers offer services across the spectrum of model types IaaS, PaaS, and SaaS.  With any of them, you can create an entire virtual network with servers accessible from anywhere in the world.  These providers also offer platform services for developers to conveniently deploy apps without worrying about the underlying operating system and infrastructure.  They also offer SaaS solutions, especially Microsoft's Office 365 and Google's Workspace (FKA G-Suite) that provide browser based applications for email, word processing, spreadsheets and presentations.

These are the three big players in the cloud space that make up the majority of the market.  AWS has the largest market share and have pioneered cloud services for many years over Microsoft and Google; however each year Microsoft has been gaining in market share.  Microsoft has a competitive advantage in this space as many organizations rely on Windows domains to manage their environments and Microsoft has been building services that align to existing customers.  This is especially true with their Entra services (FKA Azure Active Directory) which offers identity provider services for integrating identity and access management, a wildly popular service.  So popular in fact that many SaaS applications are configured with Azure Entra supporting *single sign on (SSO)* and SAML authentication.

Google Workspace is also very popular as it is a less expensive and comparable in quality to Microsoft Office 365.  Many companies use Workspace for their basic application needs which can be served to any device with a browser and shared between members of an organization.  It is very common for organizations to have a *multi cloud network* where users access several cloud providers as illustrated below.

![[../images/13/multi_cloud.png|Multi Cloud Network|350]]

Here, a developer may access AWS using the Entra identity provider to deploy an application and store their technical documentation in Google Workspace!  Having a firm knowledge of the services from the providers is a marketable skillset.  The next section will explore AWS's infrastructure services and creation of a new cloud account.
## Amazon Web Services (AWS)
AWS is the most popular cloud provider as of the time of this writing.  In many ways, AWS pioneered the space with its offering of cloud based storage solutions called simple storage solution (S3) and virtual machines called elastic compute cloud (EC2) in 2006.[^1]  This drew a crowd of administrators and developers to the platform as they could quickly deploy applications with low up front costs.  The company has grown at a fast rate and is now in 33 *regions* across the globe.  Regions consist of several physical data centers that make up *availability zones* offering regional redundancy and capacity for customers.

> [!info] Info - Private EC2
> It would be a full three years before AWS began offering virtual private cloud (VPC) services where customers could place EC2 virtual machines in private networks.  Before then, all instances were on the same network!

Cloud offerings are described as services by AWS and the count in the dozens with new services being developed and released every year.  Some of these services are more common or popular than others and usually have a non-cloud analog they are based off of.  Mentioned earlier in this section is S3, which provides a file storage solution.  Building services off of traditional on-premise concepts facilitates the knowledge transfer to the cloud.  However, these services typically only offer a simplistic generalized form of the on-premise solution.  While this makes it easier to master, it also limits the capabilities of the service versus on-premise.  If you want granular control, the cloud isn't usually the best option.  But if you are seeking ease of implementation, cloud services can get you operating within minutes.

The cloud is divided into two conceptual planes called *control plane* and the *data plane*.  The control plane is where AWS users or administrators can deploy services such as an EC2 instance.  This can be accomplished using the web console or through API calls possibly made through a CLI tool.  The control plane empowers users to administer the resources of services and their configuration but excludes the inner workings of that resource.  However, the data plane is where the service value is realized.  Using the EC2 example, the data plane is accessed when an administrator makes a terminal connection and installs then runs an application within the VM.

Maintaining access control of an AWS environment is crucial for its security.  All AWS accounts come with a *root* user that has all permissions over the account.  The root user must be protected at all costs as the loss of this principal means the loss of the entire AWS account.  AWS offers the *identity and access management (IAM)* service to create and manage users as well as their permissions.  Access can be administered through control plane where IAM user accounts are created much like any other system.  Policies with permissions can then be applied to the IAM account to give them capability to use the AWS account.

>[!activity] Activity 13.1 - Create and Setup AWS Account
>Setting up an AWS account is relatively straight forward but the service isn't free, or at least not for more than modest usage.  Therefore, AWS requires that new accounts provide a credit card when signing up to charge accrued monthly costs to.  There is no way to cap or limit this, so you must be very careful not to leave an account exposed or expensive services running.  If an attacker obtains IAM user or root account credentials, they could run up large costs that the owner of the account (you) are responsible for.  In this activity, I will demonstrate how to setup an AWS account, create an IAM user, and configure multifactor authentication for both the IAM and root users.
>
>From my host computer, I navigate to https://aws.amazon.com/  and press the "Create an AWS account" button in the top right corner.  This prompts me to enter an email address and account name before requesting an email verification.
>![[../images/13/aws_activity_signup.png|AWS Signup Page|500]]
>After submitting the form, I am prompted for a verification token on the next page.  I navigate to my email account to retrieve the token emailed to me during the previous step.  I enter the code and press the "Verify" button to establish my control over the email account.  The next page in the AWS signup wizard requires that I set a password for the root user.
>
>>[!warning] Warning - Root User Password
>> **The password should have high entropy (long and random) and not be used anywhere else!**
>
>![[../images/13/aws_activity_password.png|AWS Create Root User Password Setup|500]]
>The next page of the wizard has me enter my name, contact information, address and how I plan to use the account (I chose "Personal - for your own projects").  Then I am prompted to enter my billing information such as a credit card.  It is best to use a credit card over a debit card as the latter takes money directly from your bank account whereas the former only accrues charges which can always be disputed if there is fraudulent activity.  You could dispute fraudulent debit card charges just the same, however in the mean time you would have still had the money deducted from your bank account.
>![[../images/13/aws_activity_billing.png|AWS Billing Setup|500]]
>Pressing "Verify and continue" after entering my credit card details takes me to the phone number and proof I'm not a robot step where I have to complete a CAPTCHA.  Submitting this sends me a verification code to my phone that I enter on the following page to prove my phone number.  The last page in the wizard has me select a support plan.  Because this account is for personal use, I select the "Basic support -Free" plan and press the "Complete sign up" button.
>![[../images/13/aws_activity_support.png|Support Plan Selection|500]]
>The account is officially created!  Next I sign into the management console by pressing the "Sign In to the Console" or "Go to the AWS Management Console" buttons on the page after the initial setup.  Alternatively, I could go to https://aws.amazon.com and press the "Sign In to the Console" button in the top right corner to login at any time.  I select the "Root user" and enter my email address, press Next, and then password to login under the root user account.
>![[../images/13/aws_activity_login_root.png|Root User Login|350]]
>Now logged in as the root user, I navigate to the user settings by selecting the account drop down menu in the top right corner and select "Security Credentials."  
>![[../images/13/aws_activity_root_settings.png|Root Account Settings|250]]
>The security settings for the logged in user allow us to set credentials, changes passwords, and setup multi-factor authentication (MFA) devices.  Because the root account is so important and internet accessible, I want to setup MFA which will mitigate the risks of losing the account to an attacker guessing the root password along with the impacts that could cause.  I scroll down to the "Multi-factor authentication (MFA)" section and press the "Assign MFA device" button.
>![[../images/13/aws_activity_mfa_start.png|Root Account MFA Setup|600]]
>AWS prompts me to enter an MFA device name and MFA device.  I already have an authenticator app install on my smart phone that I use for MFA.  Some great choices are the Google or the Microsoft Authenticators apps available for free in the app stores.  I enter a name, select Authenticator app, and press the Next button.
>![[../images/13/aws_activity_mfa_selection.png|MFA Device Selection|600]]
>Pressing the "Show QR code" link in the second sub-step reveals a QR code.  With my phone's  authenticator app launched, I press the new account option which opens the camera feature on my phone.  Next I point my phone's camera to the QR code on the AWS page which instantly creates the account in my authenticator app.  I enter the first 6 digit code into the "MFA code 1" field of the AWS console page, wait 30 seconds for a new code to be generated, and then enter the second (new) code into the MFA code 2 field of the AWS console page.  Then I press the "Add MFA" button to complete the MFA device setup.
>![[../images/13/aws_activity_mfa_config.png|MFA Configuration|600]]
>Its a bad practice to use the AWS root account for normal use.  It should be used rarely which will limit the opportunity of being compromised.  A better practice is to create a new IAM account with administrator capabilities for privileged actions.  It would be awful if the admin account is compromised, but not nearly as bad as if the root account was!  In order to create the IAM account, I must open the IAM service by searching for "iam" in the top search bar.
>![[../images/13/aws_activity_iam_search.png|IAM Service Search|600]]
>The launched IAM service can be navigated using the options tree on the left pane.  To create a new user I select the "Users" link and the the "Create user" button on the page in the right pane.
>![[../images/13/aws_activity_create_user.png|IAM Service User Page|500]]
>Within the create user page, I enter my name in the "User name" field, check the box "Provide user access to the AWS Management Console" to allow web GUI access, and select the "I want to create an IAM user" option.  Then I enter a strong and high entropy password that is not used for any other account or system and unselect the "Users must create a new password at next sign-in" checkbox.  Finally I press the "Next" button to continue the account creation process.
>![[../images/13/aws_activity_create_user 1.png|Create User Settings|600]]
>The next page in the wizard is used to configure the user privileges.  While I could create custom policies with any combination of permissions, AWS comes with managed policies for common use cases.  This includes the "AdministratorAccess" policy which grants all permissions to all services.  I select the "Attach policies directly" option and mark the "AdministratorAccess" policy checkbox before pressing the "Next" button to continue the account creation.
>![[../images/13/aws_activity_policy.png|IAM User Policy Selection|600]]
>The last page summarizes all the configurations which I review and confirm is correct then press the "Create user" button to create the IAM admin user account.  The account creates successfully and I am navigated to the final step "Retrieve password" in the wizard.  This page includes a "Console sign-in URL" link which has the AWS account number embedded within it as a subdomain.  I write this number down as it is needed when logging in from the main AWS login page - otherwise I would have to log in as the root user and find the account number anytime I wanted to log in as the new IAM user.
>
>The new administrator user I just created needs MFA but the only way to set it is to login as the admin user.  My next step is to log out of the root user account and then login using the link in the previous step with my username and password.  Just like I did for the root user, I navigate to the "Security credentials" of the logged in admin user and set the MFA device.
## Defending the Cloud
In many ways, defending the security of the cloud is no different then defending traditional computer and network systems.  Fundamentally, the cloud has similar threats and mitigations as on-premise information technology.  One could argue that the cloud imposes more security risk as most organizations operate on public cloud providers, and their accounts can be accessed from anywhere.  Comparing that to a traditional on-premise network where a remote user may not be able to access the entire control plane of the network could be arguably more secure.  As demonstrated in the last section, AWS empowers users to access their AWS account and all of the account's infrastructure and data through their website which is accessible from anywhere in the world.  That access plus the concern of sharing underlying hosts with other tenants is enough to make some IT managers concerned about putting anything in the cloud.

Throughout the chapters in this textbook we have explored several staples of securing data, systems, and networks.  So much of security is about finding and mitigating vulnerabilities, protecting data with encryption, managing people and system's access and permissions, and then monitoring and responding to security threats.  These same activities are translated to cloud services at all the major cloud providers.  The cloud essentially adds a layer of abstraction to existing technology.  This existing technology is subject to the same security risks covered throughout this book; however, the cloud abstraction layer also introduces new security risk vectors.  Many cloud providers have created new security features and services that focus on these new cloud security vectors.  Continuing the focus on AWS, let's explore some of the most common security related services available to customers.

> [!tip] Tip - Other AWS Services
> There are many more AWS security services and features than what I cover in this section.  Interested readers should checkout AWS's expansive and detailed docs to learn more! https://docs.aws.amazon.com/

**Amazon Inspector** is a security service that integrates across a handful of computing related AWS services (EC2, ECR, Lambda).  It is most analogous to a traditional vulnerability management scanner but is less rich in features.  Inspector regularly scans compute instances and identifies common vulnerabilities and exposures (CVE) from a known, and frequently updated, vulnerabilities database.  It can be deployed with a few clicks and will begin reporting findings within the AWS console in a matter of hours.  The ease of implementation and integration with existing services makes it an attractive option as part of a vulnerability management program.

Data should be protected while in transit and at rest.  AWS services generally use transport layer security (TLS) to protect data while in transit between their services since all services rely on APIs.  The **AWS Certificate Manger** service empowers account holders to generate certificate authorities and signed certificates that can be used for encrypting data in transit.  This service, which is accessible through the AWS Console, integrates with other AWS services that use TLS certificates, such as Amazon CloudFront, a content delivery network (CDN) service.  AWS also offers the **Key Management Service (KMS)** to store, create, and manage encryption keys used to encrypt data at rest.  KMS includes both AWS managed and customer managed keys that integrate across many AWS services such as the simple queue service (SQS) and relational database service (RDS) among many others.

![[../images/13/kms.png|AWS Key Management Service (KMS) Console|600]]

We have already glanced into the **Identity and Access Management (IAM)** service AWS offers when we created a new IAM user in the last activity.  This service also supports creating *groups* to manage homogenous cohorts of user types associated with needed permission levels.  *Roles* are also part of this service which are used to manage access from machine entities and third parties.  For example, you can create a role that allows access AWS resources and assign the role to an infrastructure resource like and EC2 virtual machine instance.  This will allow that instance to access the service through the control plane.  It is just as easy to configure a role to allow a resource, like and EC2 instance, from another AWS account to also access your used AWS services!  

We also briefly explored the concept of *policies* during the last activity where we assigned the `AdministratorAccess` policy to an IAM user.  Custom policies can be created that define which permissions and services are allowed or denied to any entity assigned to the policy.  AWS uses *policy based access control (PBAC)* as a method of managing authorization in the cloud.  The policy itself is in a JSON format and can be written manually or developed using the AWS Console's policy editor.  The following policy allows the AWS API Gateway service to invoke a specific (although ambiguous here) Lambda function.

![[../images/13/policy.png|AWS IAM Policy Sample|450]]

Each policy includes an action section which lists the service and permission that is included in the scope of the policy block, an effect such as deny or allow, the principal the policy applies to, and a resource section that lists the specific resources within the scope of the policy.  The action and resource sections allow the administrator of the policy to define if a user can access all resources of the service or only specific ones.  For example, defining the actions to include permissions related to EC2 can be made available to all instances or a specific EC2 instance.  This format allows for as much granularity in access control as desired, but is also easy to misconfigure!

>[!warning] Warning - Principal Star
>AWS IAM policies support wildcards using the `*` symbol.  A common misconfiguration is to place a wildcard in the principal field of an IAM policy.  If this policy is attached to a resource, such as a container image, it means that any principal can access the resource including principals from other AWS accounts!

Most activity that is performed on the control plane of an AWS account is logged within an AWS service called **CloudTrail**.  The first *trail* is free but any additional trails created are priced based on usage rates.  Every time a user interacts with the AWS Console or sends commands through the API, using various tools like the AWS CLI or Terraform, the actions are logged and stored for 90 days.  Each record, or entry, can be searched and filtered using the console supporting troubleshooting and security investigations.  Many organizations transfer these logs into a SIEM for a longer retention and to correlate logs with other sources.  

![[../images/13/cloudtrail.png|AWS CloudTrail Console|600]]

AWS also offers the **GuardDuty** service which has pre-built threat monitoring rules that detect potentially malicious behavior identified through sources like CloudTrail.  While GuardDuty does not support custom rules, it does have a long list of managed rules that are essential to detect active threats, indicators of compromise, and indicators of attacks while rating them by severity.  For instance, exposing SSH to the internet on an EC2 instance will result in attackers attempting to brute force entry.  If GuardDuty is enabled, it will detect the attempts and generate an alert for security analysis.

![[../images/13/guardduty.png|AWS GuardDuty Alerts|600]]

In the Operating System Security chapter we used a benchmarking tool called Inspec by Chef.  This tool scanned our Ubuntu operating system and advise us where system settings were not as security as they could be.  There is a similar class of tools designed for the cloud call **cloud security posture management (CSPM)** where a scan is completed assessing the resources and configurations against a rules engine to draw out any potential security misconfigurations.  Snyk, which was introduced in the Web Application Defense chapter, offers a great CSPM scanner for enterprise (paid) users.  There are also free and opensource solutions such as ScoutSuite which supports all the major cloud vendors, custom rules, and ignore lists.  This class of tool is vital to the security programs of organizations that use the cloud and should be run regularly by security engineers to identify and then mitigate security vulnerabilities. 

>[!activity] Activity 13.2 - ScoutSuite CSPM
>Before running ScoutSuite against my AWS account, it needs user credentials that can read all the resources and their settings.  Its a bad practice to use an account that has anything more than read permissions, so using my admin account for this purpose is not recommended.  Organizations may want to run the tool periodically, such as daily or weekly, in an automated fashion so having a dedicated user account that is only used for the tool would be ideal.  Doing so protects the AWS and user accounts by reducing the opportunities its credentials could be compromised.  If the credentials were ever expired or rotated, only the CSPM tool would fail.  So the first thing I'll do is setup a low privileged IAM user before running the scan.
>
>I log into my AWS account using my administrator IAM user (not the root user) and navigate to the IAM service then the Users page.  I press the "Create user" button to start the user creation process and enter its name as `auditor`.  Unlike the administrator user I created in the previous activity, this user will leave the "Provide user access to the AWS Management Console" unchecked.  I also generate a long and high entropy password that isn't used anywhere else.  Because this IAM user will be used as a *service* account, it won't have MFA enabled as it isn't practical for automated machine connections.
>![[../images/13/cspm_activity_user_create.png|Create Auditor IAM User|600]]
>The next step in the wizard is to assign a policy with permissions that fits the need of the IAM user.  Because this IAM user only needs to read resources, I choose the "ReadOnlyAccess" and the "SecurityAudit" policies before pressing "Create user".
>![[../images/13/cspm_activity_policy.png|IAM Policy Setting|600]]
>I can see the newly created user `auditor` listed in the Users page within the Users section.  I'll need to generate access keys which will be used to authenticate to the AWS account when running the scan.  To set these up, I press the username link for `auditor` which takes me to the user settings page.  I then navigate to the "Security credentials" tab and scroll down to the "Access keys" section, underneath the MFA section, and press the "Create access key" button.
>![[../images/13/cspm_activity_keys.png|Creating Auditor User Access Keys|600]]
>This launches the key creation wizard where I select the "Command Line Interface (CLI)" option and agree to the confirmation before hitting "Next" and then "Create access key".
>![[../images/13/cspm_activity_cli_selection.png|CLI Key Selection|600]]
>Once the access key is created, I press the "Show" link to reveal the secret access key.  I'll copy both the "Access key", which is like the username, as well as the "Secret access key", similar to a password, values to my password manager for safe keeping and later use.  Its important I do this now as once I click off the page I won't be able to review the secret key again.  If I miss this opportunity to show the key, I'll have to destroy the old key and replace it with a new one.
>![[../images/13/cspm_activity_keys_show.png|Auditor Access Keys View|600]]
>Now that the IAM user is created, I can begin the process of installing and using ScoutSuite to perform a CSPM scan against my AWS account.  A prerequisite to the tool is the AWS CLI which can be installed through the default Ubuntu APT repositories.  I launch my Ubuntu VM in Bridge Adapter network mode, start a terminal, update my machine and the run the install command.
>```bash
>sudo apt update -y
>sudo apt install awscli -y
>```
>![[../images/13/cspm_activity_awscli.png|Installing AWS CLI on Ubuntu|600]]
>The AWS CLI needs to be fed credentials and other settings which can be stored within a profile and referenced when running ScoutSuite.  I'll name the profile `auditor` and enter the access key, the secret key, the region as "us-west-1" since that is where my default AWS region was when I created the AWS account, and JSON as the output format.
>```bash
>aws configure --profile auditor
>```
>![[../images/13/cspm_activity_aws_config.png|AWS CLI Configuration|600]]
>ScoutSuite runs best in a Python virtual environment as many of its dependencies might interfere with the Ubuntu VM's Python libraries.  Using Python virtual environments are a great way to sandbox applications and avoid such conflicts.  Before creating a virtual environment, I have to install the tool using `apt`.  
>```bash
>sudo apt install python3-virtualenv -y
>```
>![[../images/13/cspm_activity_virtenv_install.png|Installing Python Virtual Environment|600]]
>Now I can create the Python virtual environment, calling it `venv` which creates a like name folder in my current working directory.  Within the `venv` folder is a binary called activate that will start the virtual environment.  Notice that the command line changes with a preceding `(venv)` which denotes that I am working within the virtual environment.
>```
>virtualenv -p python3 venv
>source venv/bin/activate
>```
>![[../images/13/cspm_activity_start_virtenv.png|Creating and Starting Virtual Environment|600]]
>Any changes to Python libraries will be contained within this virtual environment.  I can leave the environment anytime by entering the `deactivate` command.  I'll use `pip` to install ScoutSuite.
>```bash
>pip install scoutsuite
>```
>![[../images/13/cspm_activity_install_scout.png|Installing ScoutSuite In Virtual Environment|600]]
>I'm finally ready to run my scan that will discovery any potential security misconfigurations in my AWS account.  ScoutSuite will make API calls to all AWS services using the auditor account and compare results to a rules engine that will identify any potential security flaws.  Running the following command instructs ScoutSuite to run AWS checks using the auditor profile configured earlier.
>```bash
>scout aws --profile auditor
>```
>![[../images/13/cspm_activity_scout_scan.png|Launching ScoutSuite Scan|600]]
>Once the scan is complete, an HTML report is generated and automatically opened in the VM's browser.
>![[../images/13/cspm_activity_scan_result.png|ScoutSuite Service Report|600]]
>The HTML report contains several static pages that allow me to drill down into each service and review the vulnerabilities identified by ScoutSuite.  We can see that the default AWS account could use some hardening.  One failed rule that catches my eye is in the IAM service where a policy setting is missing that could be applied to restrict unused credentials.  
>![[../images/13/cspm_activity_iam_finding.png|ScoutSuite IAM Finding|600]]
## Attacking the Cloud
Knowing that the cloud is just someone else's computer which is susceptible to the same types of attacks covered throughout this textbook, demystifies how the cloud is attacked.  It is after all just another computer and network that uses the same underlying technologies as on-premise systems.  For example, and EC2 instance running an outdated version of Windows Server is subject to the same security risks as one that runs in a private data center.  However, beyond these traditional attacks, there are a number of cloud specific security risks created by the control plane.

An attacker could feasibly launch a brute force attack against an IAM user account by attempting a number of password guesses.  If the user account's password is weak, the attacker could gain access to the AWS account's control plane.  Such an attack is largely mitigated by using a long and high entropy password.  Another similar attack is the *password stuffing* attack where the attacker uses passwords found on that user from another breached system as the basis of their password guesses.  There is a strong tendency for individuals to use the same, or slightly modified, password between systems.  However this attack is also mitigated by using a long, high entropy, and unique password.

Regardless of password strength, IAM accounts should be protected with multifactor authentication (MFA) to reduce the changes of an account takeover.  If the attacker is able to guess the password, through brute forcing or stuffing, they won't be able to login as they will be confronted with another layer of authentication.  Of course there are ways to bypass MFA such as tricking the victim user to give up their MFA token value via a phishing website or socially engineering them.  If the attacker were to somehow obtain the victim's session identifier, from their browser's cookie jar, then the attacker won't need the credentials or MFA at all as the session has already been authenticated.  There possibly other methods of bypassing MFA which are beyond the scope of this textbook and interested readers are encouraged to explore more.

>[!tip] Tip - MFA Fallacy
>It is common for many people to believe that a security control eliminates security risk.  I have witnessed many business managers, and even IT professionals, believe that it is impossible for an attacker to log into an account if MFA is enabled.  As you've read, this is definitely not the case.

Frankly, stealing users passwords, socially engineering victims, setting up phishing websites, and bypass MFA could be a lot of work for an attacker if countermeasures are in place.  Malicious actors will still try these attacks, and can be successful, but the complexity and challenge is a material deterrent for casual attackers.  However, as you learned setting up ScoutSuite in the previous activity, some IAM accounts could have access keys associated with them.  These keys are cryptographically strong and have high entropy making them difficult to guess.  But you may have noticed that when I ran ScoutSuite in the previous activity, no MFA control was present.  Possessing the keys is as good as having the username and password of an account.  Even if the account user that owns the keys has MFA enabled, the access keys do not require the additional authentication check.  This weakness provides a standing MFA bypass to an otherwise protected IAM account.  If the secret access keys can be obtained by an attacker, they would be able to access the cloud account's control plane.

>[!activity] Activity 13.3 - Leaked Credentials
>Developers tend to have a nasty habit of hard coding, or including in plain text, secrets within their source code.  This can occur incidentally, but it is often happens due to carelessness.  Sometimes developers will realize this mistake and remove the keys from their source code.  However, source code repositories that are based on `git` store all changes in the *git history*.  GitHub is a popular free code version control system for software where many individuals and organizations share source code publicly.  These public repositories are searchable using the site's regular expression search field.  A simple unauthenticated search for "remove aws credentials" yields almost one thousand results.
>![[../images/13/leaked_activity_commits.png|GitHub Leaked AWS Key Search Results]]
>I have redacted information on these commits for sake of privacy, even though they are public.  The first couple commits don't show anything interesting but the third commit on the list shows some juicy details.
>![[../images/13/leaked_activity_commit.png|Commit File Changes]]
>The left pane shows the original content while the right side shows the final content relative to this code change or commit.  Within the old code are two lines (4 and 5) of particular interest as they show plaintext access and secret keys for an AWS account.  Even though the developer removed them, they still persist in git history!  

The cloud makes the provisioning and deployment of IT solutions too easy.  So easy in fact, that anyone with little experience can do it.  This is accomplished through abstracting away the complexity of the system; however without sufficient knowledge of the underlying technology, a novice or careless user could inadvertently expose their infrastructure to security threats.  While this is feasible for on-premise networks, it is common risk in the cloud as there are more novice users that don't understand the risks of exposing infrastructure to the internet.

To make matters worse, exposing AWS resources to the internet is almost encouraged with how AWS has developed its services.  One of their goals is to provide ease of deployment by simplifying how resources are created.  While this makes deploying assets from the cloud easy, it also make exposing things to the internet that shouldn't be available to anonymous users easy.  Common misconfigurations are exposing an EC2 instance SSH service to the internet, which happens by default when deploying an instance from the AWS Console.  The cloud administrator has to purposefully not expose the EC2 to the internet with manual configuration changes.  Many AWS services suffer from this state of misconfiguration which degrades the security of customers using cloud services.

>[!activity] Activity 13.3 - S3 Buckets
>Several years ago the topic of publicly exposed S3 buckets was the source of many scary headlines in the security news media.  Countless data breaches occurred because of buckets, effectively network file systems, were made readable, and sometime writeable, to anonymous internet users.  This was caused by AWS's over simplified service to deploy S3 resources and making them public by default.  In response to these data leaks, AWS updated the console to clearly show when buckets are publicly exposed while adding additional security features to control how buckets are accessed.  
>
>An interesting project by Grayhat Warfare regularly scours cloud providers for exposed storage buckets, such as AWS's S3 service.  They identify publicly exposed buckets and index their contents making them searchable from Grayhat's website.  Navigating over to https://buckets.grayhatwarfare.com/ I see there are hundreds of thousands of identified public AWS S3 buckets. 
>![[../images/13/bucket_activity_landing.png|Grayhat Warfare Landing Page]]
>
>The search feature requires a free registered account and curtails results to tens of thousands (versus hundreds of thousands).  Premium users have access to the entire site's identified resources.  After logging in, I navigate to the "Filter Buckets" and choose "Filter Buckets" which presents me with a keywords field.  Many buckets are purposefully exposed to the public internet as they contain public files.  However, I am interested in buckets that may have been accidently exposed to the internet.  I therefore need to think of some naming conventions for buckets and objects that could reflect this.  I chose the keyword "backup" as usually system backups are not meant for public consumption.  Searching for this keyword leads thousands of buckets that potentially shouldn't be exposed to the internet.
>![[../images/13/bucket_activity_backup_buckets.png|Exposed Cloud Buckets]]
>We can see that each bucket or file contains the keyword "backup" from my search.  The first entry looks very interesting, but the hyperlink is crossed out signaling that the file no longer exists.  Someone likely exposed customer data and then promptly removed it.  I wonder if they are going to send notices to their customers that they made that error.  The second and third entries don't look too interesting but the fourth entry suggest a developer may have exposed an application backup file.  Downloading this backup file and opening within Notepad shows that it is a Postgres database backup file.  Searching it more thoroughly reveals a user table with records including email, contact number, role, and encrypted passwords!
>![[../images/13/bucket_activity_file.png|Database File Exposed|500]]

While we just covered how malicious actors could gain entry to cloud environments through credentials or misconfigured resources, the cloud's control plane also has post exploitation vulnerabilities like privilege escalation.  In the previous section, we explored the structure of AWS IAM policies and how they could be misconfigured even exposing a resource to other AWS accounts.  Most administrators would be careful when administering permissions using policies and would avoid applying the `AdminsitratorAccess` policy to subjects not needing that level of permission.  However, IAM policies are very granular and can be applied in countless ways which could allow opportunity for abuse.  For example, an account that has unrestricted IAM PassRole permissions could pass an administrator role to another resource they control effectively making them an admin!  

There are many of these privilege escalation techniques due to sensitive permission sets that have been explored in detail by Rhino Security Labs.  This team has developed a tool for detecting misconfigured policies that allow for privileged escalation called Pacu.  They have also published their research describing each vector and the conditions needed to escalate AWS permissions within a blog post AWS IAM Privilege Escalation - Methods and Mitigations (https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/).  I highly recommend you check out Rhino and their awesome research!

![[../images/13/rhino_privesc.png|Rhino Security Labs - Privesc Methods Research]]

## Exercises

> [!exercise] Exercise 13.1 - Create and Setup AWS Account
> In this task you will create an AWS account, secure the root user, and create an IAM administrator.
> >[!warning] Warning - AWS Costs
> > This activity requires you provide AWS with a credit card for any charges. If you follow the lab instructions carefully you will have little to no charges. However, charges can occur if you setup additional services or leave services running. You are responsible for any financial costs associated with the lab.  Consider monitoring the Billing service to identify any run away costs.
> #### Step 1 - Create AWS Account
>
> From your host computer, open a browser and navigate to [https://aws.amazon.com/](https://aws.amazon.com/) . Press the "Create an AWS Account" button in the top right corner. Enter your email address for the "Root user email address" and enter your name under the "AWS account name". Press "Verify email address".
> 
> After submitting the first form, you will receive a verification email from AWS with a verification code. Enter the verification code and press "Verify".
> 
> Enter a "Root user password" and confirm the value then continue to the next step. 
> 
> >[!warning] Warning - Use a Strong Root Password!
> >It is important to use a strong password to prevent your account from getting compromised and running up costs that you would be responsible for.
> 
> The next step requires your name, contact, address and use information. Complete the form with accurate data as this is how AWS can contact you if something goes wrong with your account. Select "Personal - for your own projects" for the type of account.
> 
> The next step requires you enter your billing information. You will receive little to no charges under the free tier so long as you follow the lab instructions. I'd recommend using a credit card instead of a debit card to avoid cash being removed directly from your bank account in the event there is a charge. Enter your payment information and press "Verify and Continue".
> 
> The next step requires you confirm your identity. Enter your phone number and complete the CAPTCHA.
> 
> Upon submission you will receive a text message with a numeric code. Enter the numeric code to confirm your identity.  In the final step, select "Basic support -Free" and "Complete sign up"
> #### Step 2 - Setup Root User MFA
> With your AWS account setup, sign in to the management console by pressing the "Sign In to the Console" or "Go to the AWS Management Console" on the page after the initial setup. Otherwise, navigate to [https://aws.amazon.com](https://aws.amazon.com/) and press the "Sign In to the Console" button in the upper right corner. Select "Root user" and enter the email address you used to setup the account. Next, enter your password to log in to the console as the root user.
> 
> Now that you are logged in, navigate to the user (root) settings selecting the account drop down menu in the upper right corner and pressing "Security credentials".
> 
> Press "Assign MFA device" in the Multi-factor authentication table.
> 
> Select a "Device name" and choose an MFA device. "Authenticator app" can be of your choosing, some recommended free options are Google or Microsoft Authenticator apps available for free in your phone's application store. If you don't already have one, go to your phone's application store, download and install.
> 
> With the authenticator app installed on your phone, press the add account button (or equivalent) and scan QR code option. In the browser MFA setup step, press the "Show QR code". Scan the code and enter the MFA consecutive codes as prescribed in the step's instructions. Then press "Add MFA"
> #### Step 3 - Setup IAM User
> Using the root user for administrative activities is considered a bad practice. You will create a non-root administrator IAM user for all activities in this AWS lab.
> 
> Search for "IAM" in the services search bar at the top of the screen and follow the link for the IAM service.
> 
> Select "Users" in the left navigation pane to begin the process of creating a user.
> 
> Press the "Create user" button on the Users page.
> 
> Enter your name as the "User name", check the box "Provide user access to the AWS Management Console" so the user can log into the console. Select the "I want to create an IAM user" option. Enter a strong password and unselect the "Users must create a new password at next sign-in" checkbox. Press the "Next" button.
> 
> Set the IAM user permissions to administrator by selecting the "Attach policies directly" option and marking the "`AdministratorAccess`" policy checkbox. Then press "Next".
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
> In the next step of the wizard, choose "Attach policies directly". Using the filter "AWS managed - job function", search for and select "`ReadOnlyAccess`" and "`SecurityAudit`" permission policies. Press Next and then "Create user".
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
> Once the AWS CLI is installed, configure the tool to use the "auditor" IAM credentials created in the previous step. Enter you access key, secret key, region as "us-west-2", and output format as "json"
> ```bash
> aws configure --profile auditor 
> ```
> #### Step 3 - Setup and Run Scout Suite
> Install Python virtual environment.
> ```bash
> sudo apt update -y
> sudo apt install python3-virtualenv -y 
> ```
> You will create a python virtual environment to run Scout Suite from to avoid any Python library conflicts. Create the virtual environment, install `scout`, and verify its installation. Note that you will have to re-enter the virtual environment to run scout in the future.
> ```bash
> virtualenv -p python3 venv
> source venv/bin/activate
> pip install scoutsuite 
> scout --help 
> ```
> With `scout` installed, running in a Python virtual environment, AWS CLI installed and configured with the auditor user, run a posture scan to discover any potential security misconfigurations. Scout will make API calls to all AWS services using the auditor account and compare results to a rules engine that identifies any potential security flaws. Please allow a few minutes for the scan to complete.
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

[^1]: Timeline of Amazon Web Services; Wikipedia; April 19th 2024; https://en.wikipedia.org/wiki/Timeline_of_Amazon_Web_Services