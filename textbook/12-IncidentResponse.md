# Incident Response
![][../images/12/soc.jpg]


description

Objectives
1. SOC
2. SIEMS - Splunk
3. Incident Response
4. Threat Hunting

## System Information and Event Manager (SIEM)
about
### Security Operations Center (SOC)
considerations

### SIEM Architecture
Implementing a SIEM
considerations
tools
capabilities

>[!activity] Activity 12.1 - SIEM Setup
## Threat Hunting

Methodologies
Threat Intelligence 
Process
- trigger
- investigate
- resolve
## Incident Response

Incident Response Life Cycle
Plan

>[!activity] Activity 12.2 - Security Incident
>Take a moment and consider the following questions:
>1. Define a security incident
>2. Identify 3 examples of what is a security incident
>3. Identify 3 examples of what is a security event

### Phases
Preparation
Detection and analysis
Containment & eradication
Post incident recovery

>[!activity] Activity 12.3 - Splunk Enterprise Security

## Exercises

>[!exercise] Exercise 12.1 - SIEM Setup
>In this task you will install Splunk onto your Ubuntu VM, import event data, and build queries, reports, and dashboards to analyze events.
>#### Step 1 - Install Splunk Enterprise
>Using your Ubuntu VM in Bridge Adapter network mode, launch a browser and navigate to [https://www.splunk.com/en_us/download/splunk-enterprise.html](https://www.splunk.com/en_us/download/splunk-enterprise.html) and fill out the Create Account form with you CSUS email address.
>
>Upon login you should reach the download page [https://www.splunk.com/en_us/download/splunk-enterprise.html?locale=en_us](https://www.splunk.com/en_us/download/splunk-enterprise.html?locale=en_us) .  Select Linux and download the ".deb" installer.
>
>Launch a terminal and install curl and the DEB file to install Splunk Enterprise.
>```bash
>sudo apt update -y 
>sudo apt install curl -y 
>sudo dpkg -i ~/Downloads/splunk*.deb 
>```
>#### Step 2 - Setup Splunk
>Start Splunk within your launched Ubuntu VM terminal.  When launching for the first time you will be presented with the license agreement.  Press "q" and then "y" to accept the terms.  Follow the CLI questions selecting a username and password.
>```bash
>sudo /opt/splunk/bin/splunk start 
>```
>Once the setup is complete and Splunk is running, launch a web browser within your Ubuntu VM and navigate to [http://ubuntu:8000](http://ubuntu:8000/) where you'll be presented with your stand-alone instance of Splunk Enterprise.
>
>Login with the credentials you used during the setup.
>#### Step 3 - Load Data
>From within your Ubuntu VM, launch a browser and navigate to [https://github.com/splunk/botsv3](https://github.com/splunk/botsv3) and download the "BOTS V3 Dataset".  It is about 320 MBs which may take a 10 minutes or so to download.  This dataset is a curated set of logs used in Splunk's Boss of the SOC CTF challenge.
>
>Move the downloaded botsv3 data set to "/opt/splunk/etc/apps/" and unzip the contents using gunzip and tar.
>```bash
>sudo mv ~/Downloads/botsv3_data_set.tgz /opt/splunk/etc/apps/ 
>sudo gunzip /opt/splunk/tec/apps/botsv3_data_set.tgz
>sudo tar -xvf /opt/splunk/etc/apps/botsv3_data_set.tar -C  /opt/splunk/etc/apps/ 
>```
>Restart Splunk for the upload botsv3 data set/index to become available.
>```bash
>sudo /opt/splunk/bin/splunk restart 
>```
>Once restarted navigate to [http://ubuntu:8000](http://ubuntu:8000/) and navigate to Apps and then "Search & Reporting".
>
>Change the time scope to "All time" and search the term "index=botsv3" to discover all available records.  Wait a few minutes and observe millions of events loaded.
>```SPL
>index=botsv3
>```
>#### Step 4 - SPL/Query
>With all 2 million events matched in the botsv3 index, scroll down to the Fields navigation on the left pane just below the timeline.  Select "host" and chose the "matar" host.
>
>Once selected, observe the search bar now includes "host=matar" in the query.  Append "| stats count by source" to the query and hit enter.  This query pipes all filtered matar results to the SPL command stats where all sources are counted and displayed in the Statistics tab in the results section.
>```SPL
>index=botsv3 host=matar | stats count by source 
>```
>Scroll to the bottom of the Statistics page and select the "stream:smtp" and "View Events". 
>
>Review the first result in the Events pane.  The first event should be an Outlook email from Grace Hoppy with the subject "Fw: All your datas belong to us".
>
>While still using the botsv3 index, query subject:"All your datas*" and observe there are 2 hits.  The wildcard * in SPL is a placeholder for any number of characters.  Observe the second event is the original email and has a src_ip address of 104.47.34.50.
>```SPL
>index=botsv3 subject:"All your datas*"
>```
>#### Step 5 - Reports
>The following query gathers the top 10 source IP addresses by count: index=botsv3 | stats count as cnt by host | sort cnt desc | head 10.  Once the SPL is complete, press the Save As dropdown in the top right corner and select Report.
>```SPL
>index=botsv3 | stats count as cnt by host | sort cnt desc | head 10
>```
>Title the report "Top 10 Hosts", Time Range Picker as Yes, and hit Save.
>
>Once the report is created, press the View button.
>
>Review the report and observe that it can be refreshed and exported at any time for reference.
>#### Step 6 - Visualizations and Dashboards
>In this step you will develop a radial gauge visualization to enhance our dashboard. Create a new query that counts the number of failed Windows logon attempts which could identify bruteforce attacks.
>```SPL
>source=* EventCode=4625|   stats count as cnt 
>```
>Once the query is entered, select the Visualization subtab and choose the radial gauge type.
>
>With the Radial gauge selected, choose Format, Color Ranges, and change the green range to 0-5, yellow range to 6-10, and red range to 11-20. These thresholds would typically be based off normal or expected behavior over time.
>
>Now that the gauge is configured with our thresholds, select the Save As and New Dashboard.
>
>Enter the Dashboard Title as "Monitoring", select "Classic Dashboards" and press Save to Dashboard.
>
>Select the View Dashboard button and observe our Monitoring Dashboard has the radial gauge, but it excludes a title and/or context. Press the Edit button in the upper right corner and name the section "Brute Force" and name the widget "Failed Windows Logons" then hit Save.
>#### Step 7 - Challenge
>Find at least one other event worth monitoring from a security context. It doesn't have to be a Windows Event, but you can use [https://www.xplg.com/windows-server-security-events-list/](https://www.xplg.com/windows-server-security-events-list/) for inspiration. Create a query and a Visualization (your choice on type). Configure the visualization and add it to the Monitoring Dashboard with an appropriate title. 
>
>In a short paragraph, describe why you selected the query/visualization to monitor, its relevance to security, and how to interpret the information it presents.

>[!exercise] Exercise 12.2 - Splunk Enterprise Security
>In this task you will register and complete Splunk's free eLearning course "Introduction to Enterprise Security". Splunk is one of the most popular SIEM tools in the industry. Evidencing your completion of the course is a great resume builder while expanding your knowledge in security.
>#### Step 1 - Register For Course
>Navigate to [https://www.splunk.com/en_us/training/course-catalog.html?filters=filterGroup1FreeCourses](https://www.splunk.com/en_us/training/course-catalog.html?filters=filterGroup1FreeCourses) and find the "Introduction to Enterprise Security" course.
>
>Press the Register link and then press the ENROLL button.
>
>Login to Splunk using your existing account (or create one if you don't have one).
>#### Step 2 - Watch the Assigned Videos
>Once you've enrolled in the eLearning course you may start the Video coursework. Watch the videos and take notes! You can re-watch the videos at any time as many times as you'd like.
>#### Step 3 - Take the Quiz
>After the videos are complete, you are prepared for the quiz. There are 11 multiple choice questions. You are untimed and can retake the quiz as many times as you need to without penalty. You must achieve a score of 75% or greater to pass the course. Upon successful completion of the course, you must provide screenshot evidence of your Certificate which can be viewed at the top of the course page.
>
>Congrats! Consider adding your completion of this course to your LinkedIn profile and/or your resume!