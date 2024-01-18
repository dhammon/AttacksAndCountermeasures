# Chapter 1 - Information Security

![](../images/01/lock.png)

Most organizations have information they seek to protect which has spawned the field of information security, or infosec.  Not to be confused with cybersecurity, which one could argue is a subfield of infosec, where digital systems are protected regardless of information.  In this chapter we explore organizations' approach to managing information security at an administrative level.  The reader will be introduced to models, frameworks, and definitions that enable the ability to discuss the topic with other professionals.  

**Objectives**
1. Explain the CIA triad and how it is used;
2. Identify common definitions associated with information security;
3. Learn about the various threat actors organization contend with;
4. Understand attack lifecycles;
5. Describe how organizations use governance, risk, and compliance within information security;
6. Identify business continuity and disaster recovery processes;
7. Understand identity access management processes and control models;
8. Prepare a virtual environment to be used in future labs.

## Introduction
You probably have some instinctual idea about information security.  Perhaps you have had a social media account compromised by using a weak password.  Or maybe you have participated in mandatory security awareness training at work.  Regardless, you might imagine scenarios where an attacker could gain access to data.  Take a moment and consider the following scenario:

> [!activity] Activity - USB in Parking Lot
> You pull into your normal parking space at work and rush out of your car to get into the building when you notice a USB thumb drive in the parking lot.  You pick up the drive and see the letters "HR" written on it in dark lettering.  "This looks interesting" you say to yourself.  
> - What's the harm a USB thumb drive could do to a computer/network?
> - How should you respond in this situation?
## CIA Triad
Information security is meant to protect data wherever it is located.  But what does it mean to *protect*?  A very popular model describing this protection is the **CIA Triad**.  Protection includes the confidentiality, availability, and integrity (CIA) of the information.  Usually illustrated as a triangle, each side of the triad is explained as follows:

- **Confidentiality** requires information is only accessed by authorized parties;
- **Integrity** instructs information is accurate and unadulterated; and
- **Availability** expects the information is available when it is needed.

![[../images/01/cia_triad.png|The CIA Triad|250]]

We use the CIA triad to explain the protection category of information.  Such generalized terms allow us to discuss types of risks and controls given a scenario.  It can be helpful to identify which arm(s) of the triad are effected when examining a scenario.

> [!activity] Activity - CIA Triad
> Which CIA triad arm applies to the given scenario?
> 1. Security updates to the database server caused a system outage that required a rollback.
> 2. An email was intercepted and the account number on a wire instruction document was changed to an unknown third party.
> 3. Customer client list and contact information was sent to an employee's personal email address a week before they quit.
## Definitions
There is common nomenclature used in the industry and throughout this book.  Let's take a moment and consider the terms that is frequently used in infosec by illustrating an example.  Imagine you have a stack of money that you are worried about it going missing.  So you decide to keep it in your house where you have a front door with a deadbolt.  You think it that money is safe until one day someone throws a rock through the window of your house and steals the money.  Using this scenario, let's consider the following terms

- **Risk** - losing money
- **Threat** - burglar breaking in 
- **Control** - dead bolt on the front door
- **Vulnerability** - a glass window
- **Payload** - a rock sitting in your garden
- **Exploit** - a burglar throwing the rock threw the window.

This scenario is analogous to the types of scenarios faced everyday by infosec professionals where there is a risk to information (think CIA Triad) by some unauthorized party.  We spend our days assessing and implementing security controls to mitigate the inherent risk of the information yet still find vulnerabilities in systems and processes that could expose the information to the risk.  If a threat is successful, and the risk realized, a security incident occurs caused by the exploitation of a vulnerability using a payload.  Let's explore what types of threats organizations face in the next section.
## Threat Actors
It is people that hack into computer systems.  Defining who and what their motivations are can aide infosec professionals by identifying types of attacks to expect.  Knowing an advisary's motivation may reveal expected patterns to be on the ready for.  The non-exhaustive table below describes some of the common **threat actor** cohorts organizations are up against.

| Threat Actor | Description | Motivation |
| ---- | ---- | ---- |
| Insider | A trusted entity, such as an employee or vendor, that has access to information and systems.  Not always technically sophisticated and often working alone. | Monetary, personal gain, revenge |
| Nation-State | Highly technical and well funded groups of hackers sponsored by the country they reside in.  Military groups tasked with gaining advantage over adversaries.  Sometimes referred to advanced persistent threats (APTs). | Espionage, military, Rarely monetary |
| Hacktivist | Geographically distributed groups consisted of volunteers that target such as governments, companies, and individuals for political.  Commonly use denial of service and defacements techniques to cause impact. | Political, ethics, beliefs. |
| Script Kiddie | AKA "skids" are individuals experimenting with attacks on opportunistic targets typically leveraging existing techniques and out-of-the-box tools. | Curiosity, learning, bragging rights. |
| Cybercriminal | Federation of criminal groups, each specializing in phases of an attack, that extort victims using ransomware and denial of service. | Monetary |

Prominent groups like Lazarus (nation-state) and Evil Corp (cybercriminal) are tracked by the MITRE in their ATT&CK knowledge base in [https://attack.mitre.org/groups/](https://attack.mitre.org/groups/).
## MITRE ATT&CK
The MITRE organization continuously tracks, monitors, and catalogs threat actors and their tools, techniques, and procedures (TTPs) which can be found at [https://attack.mitre.org/](https://attack.mitre.org/).  The ATT&CK framework reads left to right progressing through a logical and mostly linear attack lifecycle.  Not every attack uses each of these lifecycle phases (columns) or techniques listed.  But almost every attack's techniques can be mapped back to the ATT&CK examples.

> [!activity] Activity - Explore MITRE ATT&CK
> Take some time to gain familiarity with the ATT&CK Matrix at [https://attack.mitre.org/](https://attack.mitre.org/).  Review each phase and find some techniques that look intriguing to explore.  Many infosec professionals use these categories during security incident response activities and it is a great resource to learn from.
> 
> ![[../images/01/mitre_att&ck.png|Screenshot from MITRE website]]
## Cyber Kill Chain
Another reputable and commonly referenced attacker lifecycle framework is Lockheed Martin's Cyber Kill Chain® discussed at [https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html).  Knowing how an attack is methodically conducted, or how to conduct one, benefits infosec professionals by providing a model that organizes and standardizes an operation.  Lockheed's framework consists of 7 phases as described by the framework:
1. **Reconnaissance** - Harvesting email addresses, conference information, etc
2. **Weaponization** - Coupling exploit with backdoor into deliverable payload
3. **Delivery** - Delivering weaponized bundle to the victim via email, web, USB, etc
4. **Exploitation** - Exploiting a vulnerability to execute code on victim's system
5. **Installation** - Installing malware on the asset
6. **Command & Control** - Command channel for remote manipulation of victim
7. **Actions on Objectives** - With 'Hands on Keyboard' access, intruders accomplish their original goals
## Governance, Risk and Compliance (GRC)
Organizations concerned by the risks imposed by their information and systems will typically establish, to some degree of formality, an information security department.  Sometimes the concern is driven by risk owners or some other interested party like a customer, partner, or regulator that insists the organization take information and systems risks seriously.  The manner in which an organization formally establishes, manages, and communicates information security is referred to as governance, risk, and compliance (GRC) within the industry.
## Governance
Deciding how to establish and implement security in an organization can require the coordination of many managers, departments, and teams.  This is usually accomplished by establishing roles and responsibilities which are prescribed within the organizations policies and procedures.  Security should be integrated throughout the organization and technologies using a **defense in depth** strategy.  These efforts help to create a security culture where everyone knows their security duties and impacts.
### Roles and Responsibilities
There are no strict rules all organizations adhere to when determining titles and organization structure when it comes to security.  Some organizations, usually small, don't have anyone explicitly responsible while other organizations, typically larger ones, have one or more departments and hundreds of employees dedicated to specific security roles.  

Security departments are divided into areas of interest and discipline.  Most businesses have dedicated sub-departments and teams for the following functions.  We will explore many of these functions throughout the book:

- Governance, Risk, and Compliance (GRC)
- Application Security
- Security Operations
- Security Engineering
- Incident Response
- Network Security
- Identity Access Management
- *and more!*

Medium to large businesses may have a Chief Information Security Officer (CISO) who is a c-suite employee responsible for establishing the information security practices and reporting their results to the board of directors and the rest of the executive management.  Next, reporting to the CISO, may be one or more Vice President (VP) of Security dedicated to some security function of the organization, such as the security operations center or application security.  The VP(s) oversee their area of the overall security department and typically have one or more Director of Security reporting to them.  Like a VP, a Director of Security will oversee some component of the overall security department.  For instance, the Director may oversee the incident response teams of the security operations center.  Usually the Director will have one or more Security Managers reporting to them who manage security teams dedicated to a function (eg incident response).  A security team may have a mix of team members that can include Security Architects, Security Engineers, and Security Analysts.  These team members, known as *individual contributors* as they usually don't manage other employees, work together to deliver the security function they are assigned, such as responding to incidents.  A Security Architect typically contributes by providing designs of security systems, communication protocols, and documentation.  The Security Engineer works to implement such systems suggested by the Architect while the Security Analyst uses the implemented security systems.

Each of the roles may be further broken into degrees of experience such as junior, senior and principle.  Entry level or 1-2 years of experience for a given role may be assigned as a junior.  For example, as a Junior Security Engineer.  Senior level usually correlates to 2-5 years experience in the given area while a Principle has many years experience.  The years of experience described here are anecdotal and will vary depending on the individual and organization's expectations.
### Policies and Procedures
Security standards at an organization are usually communicated in the form of policies and procedures (P&Ps).  Generally policies are written by the organization's management and approved by the board of directors.  Well written policies describe the expectations of employees and how they are held accountable.  Policies may also provided directive on how the organization will operate.  Security policies may take several, sometimes dozens, of pages and explain who must do what.  Consider the following security policy statement:

> *"System administrators must review user account status and permission levels each quarter to insure no user has unneeded access to the system."*

This policy statement requires a role (system administrator) to perform a security activity (access reviews), on a timely basis (quarterly).  A policy usually doesn't go into detail on how the role performs the prescribed duty.  Instead, another written document called a procedure is used to detail the steps needed to complete the duty.  Using the same theme of an access review, a standard procedure might look like the following:

>*"The administrator logs into the system and pulls the "accounts" report from the management page.  Each account from the report is cross referenced to an employee list provided by the human resources department.  Discrepancies between the reports are validated with the user account's manager before setting the account to inactive status."*
### Culture and Defense in Depth
Everybody in an organization is responsible for security.  In fact, most of security is handled by non-security personnel at an organization.  Consider an employee who receives a phishing email.  They must make the right decision by not clicking on the email and reporting it to the security team.  Sure there are security administrators who could prevent the email from reaching the user's inbox though an email gateway or spam filter; however, it is ultimately up to the individual to make the right decision.  Consider another example of a system administrator.  The administrator must make the right decisions when deploying new infrastructure by ensure a system is up to date with security patches.  The cumulative effect of individuals knowing what the right decisions are and making the secure choices is the spirit of an organization's *security culture*.

Having a strong security culture goes a long way in keeping the organization safe from threats.  Another component that contributes the the overall security standing of an organization is the architecture of where security is implemented.  If you had some valuable jewelry you wanted to secure you may store it in a safe with a strong combination, and store that safe in a house with a deadbolt on the front door.  Depending on how safe you wanted to make that jewelry you may install a cameral and an alarms system, perhaps your neighborhood has a gate to keep non-neighbors out.  Layer upon layer of security control can be added making the jewelry safer and safer.  With each layer added the jewelry is more safe, but it is never fully safe.  This principal of adding controls over a continuum of demarcations is referred to as *defense in depth* or *layered security*.  The idea is that no single security control is full proof and adding layers of security controls commensurate with the value of what you are protecting ensures that if any single layer fails, a following layer may protect that asset.

Suppose we want to keep an organizations information or data secure using the defense in depth methodology.  We might consider how we might secure the layers depicted in the following image.

![[../images/01/defense_depth.png|Defense in Depth|500]]
The figure Defense in Depth provides a map of where we could consider adding security.  For example, the data layer could be protected by encrypting the data at rest (where it resides), users could be secured by using multifactor authentication, the application layer secured using signed binaries, the endpoint layer may have security updates regularly applied, the network layer could define a network segmentation strategy, and finally the perimeter layer could consist of a firewall that blocks unwanted traffic.  There are many more security controls each layer could potentially have.  Subsequent chapters will provide several controls in each of the layers listed here.
## Risk
Security is often considered a risk management function of an organization.  There is "security risk" to be considered operationally and that risk has a high impact.  A security incident can an organization its entire existence should the loss of data or business be so severe the organization ceases to operate.  Larger organizations sometimes have risk management departments that attempt to measure the level of risk an organization is exposed to over time and then how to manage that risk to appropriate levels.  These risk measurements helps executive management allocated resources (human, financial, etc) to areas of the organization that imposes the greatest risks.  Regardless of the size of the organization, mature security departments measure security risks to best understand where department resources should be spent.  This section explores the general methodologies used by security teams to define, measure, and manage security risk.

> [!info] What is security risk?
> *"The risk to organizational operations (including mission, functions, image, reputation), organizational assets, individuals, other organizations, and the Nation due to the potential for unauthorized access, use, disclosure, disruption, modification, or destruction of information and/or a system."* - NIST SP 800-12 Rev.1
### Qualitative Risk Management
Most security departments attempt to measure security risk using qualitative and non-ordinal ratings such as high, medium, and low.  Even if the team uses numbers instead of high-low ratings they still could be considered qualitative.  We will explore quantitative measures in the next section.  Those tasked with measuring security risk qualitatively will determine ratings using a risk matrix comprise of ratings for *likelihood* (Y axis) and *impact* (X axis) in a matrix.
![[../images/01/qual_matrix.png|Risk Matrix|400]]
The risk analyst would first determine the rating for likelihood as high, medium or low.  Next, they will assess the level of impact using the same rating scheme.  Finally, they would cross reference these two measures on the risk matrix to evaluate the risk level.  For example, a "high" impact and "low" likelihood assessment yields a "medium" risk level.

The qualitative risk management methodology is easy to conceptually grasp and measures are subjective.  There is good value in it as a tool to measure and communicate security risk levels; however, there are plenty of criticism with the methodology.  Many professionals will find that the risk ratings are not granular enough, or they might find that the measurements of likelihood or impact are non-scientific.  Regardless of its shortcomings, it is a very common approach to measuring security risk.
### Basic Quantitative Risk Management
A quantitative and slightly more sophisticated approach to measuring security risk estimates the *annual loss expectancy* by multiplying a *single loss expectancy by the estimated *annual rate of occurrence*.  The single loss expectancy is determined by multiplying the estimated *asset value* by an *exposure factor*.  The following scenario illustrates the use of this basic quantitative risk measurement:

> A database has 100,000 customer records.  Each record is estimated to cost $5 in a breach.  The asset value of the database is therefore $500,000.  If the database was breached only half the data would be exposed because it is in plain texted - while the other half is encrypted - making the exposure factor equal to 0.5.  The asset value of $500,000 times the exposure factor of 0.5 produces a single loss expectancy of $250,000.  Using industry reports, risk managers have determined that companies suffer database breaches at a rate of 5% which informs the annual rate of occurrence.  Multiplying the single loss expectancy of $250,000 by the annual rate of occurrence 5% gives the annual loss expectancy of $12,500.

Using the above calculations, a security risk manager can estimate that the business has a $12,500 risk.  That risk manager will carry out similar estimates and calculations for all assets, summing the results to produce a final risk calculation in dollar terms.  Translating risk into dollars treats the information in a form all business managers can understand since all business managers understand costs.  This measurement taken over time also can identify the trend of risk moving up or down.  The basic quantitative risk practice is considered more accurate than the qualitative method previously discussed.  However, it assumes a static likelihood while the real world may have more dynamic probability of occurrences.
### Advanced Quantitative Risk Management
Mature risk management functions or security departments may elect to use advance quantitative risk methods to measure risk.  Basic quantitative measurements use a static likelihood value while advance methods use a probabilistic model.  A risk manager will list risks and assign each one a probability value between 0 and 1 (for example 0.3).  Next each risk will be assigned a lower and upper bound loss range to a 90% confidence interval.  You may be wondering how the 90% confidence interval of loss ranges are determined.  It could be as simple as surveying 10 professionals their educated opinion what a loss may be.  Then removing the highest and lowest estimate of the 10.  Finally the risk manager will calculate the annual expected loss using a machine calculation of random probability and loss value from a normal distribution.  This can be accomplished using Microsoft Excel's *norminv* function as follows and summing all risk values calculated as illustrated in the following figure.

![[../images/01/adv_quant_table.png|Advanced Quantitative Risk Calculations]]
There are fair criticism of this method of risk calculation such as relying on estimates from individual and use of a normal distribution for convenience of easier math.  Real world observations would be ideal over subjective estimates and have the additional benefit of providing the actual distribution to be fitted.  However, this volume of data likely does not exist.  I highly recommend Douglas W. Hubbard's book "How to Measure Anything In Cybersecurity Risk" if you have further interest in security risk management.

![[../images/01/book_cover_risk.png|Quantitative Risk Measurement Recommended Reading|250]]
### Security Control Types
After risks are identified and measure a risk department can prioritize risks to control.  Risks can be controlled using a few control types.  *Administrative* controls include artefacts like policies, procedures, and written job duties.  Another popular administrative control is a review, such as the access review mentioned earlier in this chapter.  The *physical* control type has a tangible form such as a door with a deadbolt lock.  Finally, *technical* controls may be digital such as the technology that implements checking usernames and password combinations before granting access to data.  Regardless of the control type used, they all have some security goal they are attempting to achieve.
### Security Control Goals
Each control identified will naturally have one of the following goals:

| Goal | Description | Example |
| ---- | ---- | ---- |
| Preventative | Forestall the risk from occurring | Data Encryption |
| Detective | Identify the occurrence of the risk | Intrusion Detection System (IDS) |
| Deterrent | Dissuade the risk from happening | Flood Lights |
| Corrective | Fix the impact of the risk | Account Lockout |
| Compensate | Indirectly control the risk | Account Monitoring |
| Transfer | Impose the risk onto another entity. | Insurance |
| Avoid | Withdraw from the risk | Disconnect Internet |
A risk can, and probably should, have more than one control with a diverse set of goals.  For instance, preventing and detecting controls are very common when mitigating risk.  

### Risk Mitigation Considerations
Control types and control goals are not the only considerations when considering what controls to implement.  Security managers need to consider the strength of the control.  A weak control won't fully accomplish its goal whereas a strong control might.  The cost of a control must also be carefully considered as you wouldn't want to spend more on a control than the cost of the realized risk!  Another factor for consideration is the time to implement as it is not uncommon for a security department to purchase a security solution and underestimate the amount of effort it takes to adequately implement it.  In fact, the term *shelfware* has stemmed from company's buying security controls and never getting around to implementing them.  Finally, a decision can be made by the management for the adoption or rejection of a control.

## Compliance
### Laws and Regulations
- USC vs CFR
- FERPA
- GLBA
- FISMA
- HIPAA
- GDPR
- SOX
- CCPA
- NYDFS
### Frameworks and Guidelines
- CIS
- NIST 800-53 RMF
- FedRAMP
- PCI/DSS
- FFIEC
- CSA

### Audit
- SOC2
- ISO 27001

## Business Continuity Planning and Disaster Recovery
BCP/DR
### Risk Assessment
- Natural
- Technical
- People
### Business Impact Assessment
BIA

### Measures
- Recovery Point Objective (RPO)
- Recovery Time Objective (RTO)
- Max Tolerable Downtime (MTD)

### BCP/DR Plan

## Data Classification
- Private
	- Confidential
	- Internal
	- Public
- Public
	- Top Secret
	- Secret
	- Unclassified

## Identity Access Management
IAM
AAA
- Authentication
- Authorization
- Accounting

### Identity and Factors

### Permissions
- Need to know
- Least Privilege

### Access Control 
- Access Control List
- Mandatory Access Control
- Discretionary Access Control
- Role Based Access Control 

### Managing IAM
- Provision
- Review
- Revoke

## Lab Environment

> [!exercise] Exercise - Lab Environment
> Virtual Box and VMs

