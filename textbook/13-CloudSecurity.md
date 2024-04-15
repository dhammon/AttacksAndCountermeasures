# Cloud Security
img

desc

**Objectives**
1. Explain how organization use the cloud and the services they offer.
2. Create and configure an AWS cloud account with users of various permission levels
3. Understand the basic AWS security services and how to harden AWS accounts using CSPM.
4. Distinguish between traditional network and system attacks and methods for attacking cloud services.
### Cloud Overview
Cloud Models
Cloud Characteristics
Service Models
Responsibility Matrix
Cloud Providers
Popular Enterprise Cloud Services
Multi Cloud Network
### Amazon Web Services
AWS Regions
AWS Services
>[!activity] Activity 13.1 - Create and Setup AWS Account
### Defending the Cloud
Cloud Security
AWS Key Management Service
AWS CloudTrail
AWS GuardDuty
AWS IAM
IAM Policies
Cloud Security Posture Management
>[!activity] Activity 13.2 - ScoutSuite CSPM
### Attacking the Cloud
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

