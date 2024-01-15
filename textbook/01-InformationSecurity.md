# Chapter 1 - Information Security

![](../images/lock.png)


Most organizations have information they seek to protect which has spawned the field of information security, or infosec.  Not to be confused with cybersecurity, which one could argue is a subfield of infosec, where digital systems are protected regardless of information.  In this chapter we explore organizations' approach to managing information security at an administrative level.  The reader will be introduced to models, frameworks, and definitions that enable the ability to discuss the topic with other professionals.  

Objectives
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

![[../images/cia_triad.png|The CIA Triad|250]]
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
> ![[../images/mitre_att&ck.png|Screenshot from MITRE website]]

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
Deciding what
### Roles and Responsibilities

### Policies and Procedures
### Culture and Defense in Depth

## Risk

### Qualitative Risk Management

### Basic Quantitative Risk Management

### Advanced Quantitative Risk Management

### Security Control Types
- Administrative
- Physical
- Technical

### Security Control Goals
- Preventative
- Detective
- Deterrent
- Corrective
- Compensating

### Risk Mitigation Considerations
- Type
- Strength
- Decisions
- Cost
- Time

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

