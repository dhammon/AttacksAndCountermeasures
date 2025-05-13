<span class="chapter-banner">Chapter 1</span>
# Information Security

![](../images/01/lock.png)

**Objectives**
1. Explain the CIA triad and how it is used;
2. Identify common definitions associated with information security;
3. Learn about the various threat actors which organizations contend;
4. Understand attack lifecycles;
5. Describe how organizations use governance, risk, and compliance within information security;
6. Explore business continuity and disaster recovery processes;
7. Understand identity access management processes and control models; and
8. Prepare a virtual environment to be used in future labs.

Organizations typically handle sensitive information that would cause harm if accessed or manipulated by an unauthorized third party.  The operations, services, and products of these organizations often depend on computerized systems.  If such systems were degraded or unavailable the organization would be materially harmed.  These risks drive the field of information security (infosec) as organizations need the ability to operate without data or system compromise.  Infosec should not be confused with cybersecurity, which one could argue supersedes infosec, where digital systems are protected regardless of the information they process.  In this chapter, we explore how organizations approach managing information security at an administrative level.  The reader will be introduced to models, frameworks, and definitions that provide a sound foundation when discussing security with other professionals.  
## Introduction
You probably have some instinctive ideas about information security.  Perhaps you have had a social media account compromised by using a weak password, or maybe you have participated in mandatory security awareness training at work.  Regardless, you might imagine scenarios where an attacker could gain access to data.  Take a moment and consider the following scenario:

> [!activity] Activity - USB in Parking Lot
> You pull into your normal parking space at work and rush out of your car when you notice a USB thumb drive in the parking lot.  You pick up the drive and see the letters "HR" written in dark lettering on the shaft of the drive.  "This looks interesting," you say to yourself.  
> - What's the harm a USB thumb drive could do to a computer/network?
> - How should you respond in this situation?
## CIA Triad
Information security is meant to protect data wherever it is located.  But what does it mean to protect?  An immensely popular model describing this protection is the **CIA Triad**.  Protection includes the confidentiality, availability, and integrity (CIA) of the information.  Usually illustrated as a triangle, each side, or *arm*, of the triad is explained as follows:

- **Confidentiality** requires that information is only accessed by authorized parties;
- **Integrity** ensures that information is accurate and unaltered; and
- **Availability** expects that the information is available when it is needed.

![[../images/01/cia_triad.png|The CIA Triad|200]]

Security professionals use the CIA triad to explain how to protect information by applying controls on one or more sides of the triangle.  These categories allow us to discuss types of risks and controls in a scenario.

> [!activity] Activity - CIA Triad
> Which CIA triad arm applies to the given scenario?
> 1. Security updates to the database server caused a system outage that required a rollback.
> 2. An email was intercepted and the account number on a wire instruction document was changed to an unknown third party.
> 3. Customer client list and contact information was sent to an employee's personal email address a week before he quit.
## Definitions
There is a common nomenclature used in the industry and throughout this book.  Let's take a moment and consider the terms that are frequently used in security using an illustrative example.  Imagine you have a stack of money that you are worried about going missing.  You decide to keep it in your house where you have a front door with a deadbolt.  You think that the money is safe until one day someone throws a rock through the window of your house and steals the money.  Let's consider the following terms and how they relate to the scenario just described:

- **Risk** - losing money
- **Threat** - burglar breaking in 
- **Control** - dead bolt on the front door
- **Vulnerability** - a glass window
- **Payload** - a rock sitting in your garden
- **Exploit** - a burglar throwing the rock through the window.

This example is analogous to the types of scenarios faced everyday by infosec professionals where there is a risk to information (think CIA Triad) by some unauthorized party.  We spend our days assessing and implementing security controls to mitigate the inherent risk of the information.  A security incident occurs when a threat is successful, such as when the risk is realized by exploitation of a vulnerability using a payload.  Let's explore the types of threats organizations face in the next section.
## Threat Actors
People that hack into computer systems are commonly referred to as **threat actors**.  Defining who and what their motivations are can aid infosec professionals when designing security systems.  Centralizing a database of adversaries and their attack methods enables professionals to deduce or attribute which attacker conducted a breach.  The observed behaviors, attack patterns, tools used, and impacts caused leave a sort of fingerprint that could be traced back to a known and documented attacker.  

Prominent groups like Lazarus (nation-state) and Evil Corp (cybercriminal) are tracked by the MITRE organization's ATT&CK knowledge base and can be found at [https://attack.mitre.org/groups/](https://attack.mitre.org/groups/).  This collection of threat actors is used by security professionals when performing analysis, such as during an incident response, to identify which group potentially attacked them.

The non-exhaustive table below describes some of the common threat actor cohorts that organizations are up against.

| Threat Actor  | Description                                                                                                                                                                                                                      | Motivation                            |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| Insider       | A trusted entity, such as an employee or vendor, that has access to information and systems.  Not always technically sophisticated and often working alone.                                                                      | Monetary, personal gain, revenge      |
| Nation-State  | Highly technical and well-funded groups of hackers sponsored by the country in which they reside.  Military groups tasked with gaining advantage over adversaries.  Sometimes referred to as advanced persistent threats (APTs). | Espionage, military, rarely monetary  |
| Hacktivist    | Geographically distributed groups consisting of volunteers that target governments, companies, and individuals for political reasons.  Commonly use denial of service and defacements techniques.                                | Political, ethics, beliefs.           |
| Script Kiddie | AKA "skids" are individuals experimenting with attacks on opportunistic targets typically leveraging existing techniques and out-of-the-box tools.                                                                               | Curiosity, learning, bragging rights. |
| Cybercriminal | Federation of criminal groups, each specializing in phases of an attack, that extort victims using ransomware and denial of service.                                                                                             | Monetary                              |

## MITRE ATT&CK
Besides tracking threat actor groups, the MITRE organization also tracks, monitors, and catalogs threat actor tools, techniques, and procedures (TTPs), which can be found at [https://attack.mitre.org/](https://attack.mitre.org/).  The ATT&CK framework reads left to right progressing through a logical and mostly linear attack lifecycle.  Not every attack uses each of these lifecycle phases (columns) or techniques listed, but most attack techniques can be mapped back to an ATT&CK item.

> [!activity] Activity - Explore MITRE ATT&CK
> Take some time to gain familiarity with the ATT&CK Matrix at [https://attack.mitre.org/](https://attack.mitre.org/).  Review each phase and find some techniques that look intriguing to explore.  Many infosec professionals use these categories during security incident response activities and it is a great resource for learning.
> 
> ![[../images/01/mitre_att&ck.png|Screenshot from MITRE website]]
## Cyber Kill Chain
Another reputable and commonly referenced attacker lifecycle framework is Lockheed Martin's Cyber Kill Chain® discussed at [https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html).  Knowing how an attack is methodically conducted, or how to conduct one, benefits infosec professionals by providing a model that organizes and standardizes an operation.  Lockheed's framework consists of seven phases, as described by the framework:

1. **Reconnaissance** - Harvesting email addresses, conference information, etc
2. **Weaponization** - Coupling exploit with backdoor into deliverable payload
3. **Delivery** - Delivering weaponized bundle to the victim via email, web, USB, etc
4. **Exploitation** - Exploiting a vulnerability to execute code on victim's system
5. **Installation** - Installing malware on the asset
6. **Command & Control** - Command channel for remote manipulation of victim
7. **Actions on Objectives** - With 'Hands on Keyboard' access, intruders accomplish their original goals
## Governance, Risk and Compliance (GRC)
Organizations concerned by the risks imposed by their information and systems will typically establish, to some degree of formality, an information security department.  Sometimes the concern is driven by risk owners or some other interested party like a customer, partner, or regulator that insists the organization take information and system risks seriously.  The way an organization formally establishes, manages, and communicates information security is called governance, risk, and compliance (GRC) within the industry.
## Governance
Establishing and implementing a security system in an organization can require the coordination of many managers, departments, and teams.  This is usually accomplished by establishing roles and responsibilities which are prescribed within the organization's policies and procedures.  Security should be integrated throughout the organization and technologies using a **defense in depth** strategy in which multiple layers of security control are integrated throughout processes and technologies.  These efforts help to create a security culture where everyone knows their security duties and impacts.

> [!tip] Tip - Security Culture is Everything
> It is my opinion that security culture is the most important thing to keep an organization secure.  Security is the responsibility of every individual at an organization and requires everyone to make the right decision at the appropriate moment.  Everyone must care about security and have the knowledge needed to make sound choices.  For example, someone in accounting needs to know when they are being phished, or a developer needs to understand what a SQL injection vulnerability is if an organization is to have any hope of remaining secure.
### Roles and Responsibilities
There are no strict rules all organizations adhere to when determining security titles and organization structure.  Some organizations, often small, do not have an individual explicitly responsible for the security of systems and data.  Other organizations, typically larger ones, have one or more departments and hundreds of employees dedicated to specific security roles.  Where they exist, security departments are commonly divided into areas by discipline.  Most large businesses will have dedicated sub-departments and teams for the following functions:

- Governance, Risk, and Compliance (GRC)
- Application Security
- Security Operations
- Security Engineering
- Incident Response
- Network Security
- Identity Access Management
- and more!

Medium to large businesses may have a Chief Information Security Officer (CISO) who is a c-suite employee responsible for establishing the information security practices and reporting results to the board of directors and executive management.  Next, reporting to the CISO, may be one or more Vice Presidents (VP) of Security dedicated to some security function of the organization, such as the security operations center or application security.  The VP(s) oversee the security area and typically have one or more Directors of Security reporting to them.  Like a VP, a Director of Security will oversee some component of the overall security department.  For instance, the Director may oversee the incident response teams of the security operations center.  Usually, the Director will have one or more Security Managers reporting to her who manage security teams dedicated to a function like incident response.  A security team may have a mix of team members that can include Security Architects, Security Engineers, and Security Analysts.  These team members, known as *individual contributors* because they usually do not manage other employees, work together to deliver the security function they are assigned, such as responding to incidents.  A Security Architect typically contributes by providing designs of security systems, communication protocols, and documentation.  The Security Engineer works to implement systems designed by the Architect.  The Security Analyst uses the security systems implemented by the Security Engineer.

>[!info] Info - Security Functions
>The previous paragraph uses the incident response function as an example to illustrate the titles that could be used in a large department, however, there are many other teams an organization may have.  Other teams may include, but are not limited to, application security, security engineering, SOC administration, reverse engineering, malware analysis, and many more.

Each role may be further broken into degrees of experience such as junior, senior, staff and principal.  They may be further divided by levels such as 1, 2, and 3.  Entry level or 1-2 years of experience for a given role may be assigned as a junior, such as a Junior Security Engineer.  Senior level usually correlates to 2-5 years of experience in the given area while a Principal has more years of experience.  The years of experience described here are anecdotal and will vary depending on the individual and organization's expectations.
### Policies and Procedures
Security standards at an organization are usually communicated in the form of policies and procedures (P&Ps).  Generally, policies are written by the organization management and approved by the board of directors.  Well written policies describe the expectations of employees and how they are held accountable.  Policies may also provide directives on how the organization will operate.  Security policies may take several, sometimes dozens, of pages and explain who must do what.  Consider the following security policy statement:

> *"System administrators must review user account status and permission levels each quarter to ensure no user has unneeded access to the system."*

This policy statement requires a role (system administrator) to perform a security activity (access reviews), on a timely basis (quarterly).  A policy usually does not go into detail on how the role performs the prescribed duty.  Instead, another written document called a *procedure* is used to detail the steps needed to complete the duty.  Continuing the policy statement above regarding access reviews, a standard procedure might look like the following:

>*"The administrator logs into the system and pulls the "accounts" report from the management page.  Each account from the report is cross-referenced to an employee list provided by the human resources department.  Discrepancies between the reports are validated with the user account's manager before setting the account to inactive status."*
### Culture and Defense in Depth
Everybody in an organization is responsible for security.  In fact, most security is handled by non-security personnel at an organization.  Consider an employee who receives a phishing email.  He must make the right decision by not clicking on the email and reporting it to the security team.  Sure, there are security administrators who could prevent the email from reaching the user's inbox though an email gateway or spam filter, however, it is up to the individual to make the right decision.  Let's examine another example of a system administrator's duties being performed securely.  The administrator must make the right decisions when deploying new infrastructure by ensuring the system is up to date with security patches.  The cumulative effect of individuals knowing what the right decisions are and making the secure choices is the spirit of an organization's *security culture*.

Having a strong security culture goes a long way in keeping the organization safe from threats.  Another component that contributes to an organization's overall security standing is its security architecture.  If you had some valuable jewelry you wanted to secure, you may store it in a safe with a strong combination, and store that safe in a house with a deadbolt on the front door.  Depending on how safe you wanted to make that jewelry, you may install a camera and an alarm system.  Perhaps your neighborhood has a gate to keep non-neighbors out.  Layer upon layer of security control can be added strengthening the safety of the jewelry.  With each layer added, the jewelry is safer, but it is never fully safe.  This principle of adding controls over a continuum of demarcation points is referred to as *defense in depth* or *layered security*.  The idea is that no single security control is foolproof.  Adding layers of controls commensurate with the value of what you are protecting ensures that if any single layer fails, a following layer may protect that asset.

Assume we want to keep an organization's information or data secure using the defense in depth concept.  The start of that effort is to identify all the layers between a threat and the data we are trying to protect.

![[../images/01/defense_depth.png|Defense in Depth|400]]

The Defense in Depth figure provides a map of security boundaries.  For example, the data layer could be protected by encrypting the data at rest (where it resides), users could be secured by configuring multifactor authentication, the application layer could be secured using signed binaries, the endpoint layer could have security updates regularly applied, the network layer could apply a network segmentation strategy, and finally the perimeter layer could consist of a firewall that blocks unwanted traffic.  There are many more security controls each layer could potentially have to mitigate risks to the data even further.
## Risk
Security is usually considered a risk management function for an organization.  Security is categorized as an operational risk that could have a high to severe impact.  A single security incident can be so severe that it threatens an organization's entire existence.  If the loss of data or systems is extreme enough, the organization permanently ceases to operate.  Larger organizations sometimes have risk management departments that attempt to measure the level of risk an organization is exposed to over time.  It also measures how to manage that risk to tolerable levels.  These risk measurements help executive management allocate resources (human, financial, etc) to areas of the organization that impose the greatest risks and make informed business decisions.  Regardless of the size of the organization, mature security departments measure security risks to best understand where department resources should be spent.  This section explores the general methodologies used by security teams to define, measure, and manage security risk.

> [!info] Info - What is security risk?
> *"The risk to organizational operations (including mission, functions, image, reputation), organizational assets, individuals, other organizations, and the Nation due to the potential for unauthorized access, use, disclosure, disruption, modification, or destruction of information and/or a system."* - NIST SP 800-12 Rev.1
### Qualitative Risk Management
Most security departments attempt to measure security risk using qualitative and ordinal ratings such as high, medium, and low.  Even if the team uses numbers instead of high-low ratings, they still could be considered qualitative.  We will explore quantitative measures in the next section.  Those tasked with measuring security risk qualitatively will determine ratings using a risk matrix comprised of measures for *likelihood* (Y axis) and *impact* (X axis) as shown in the following matrix graphic.
![[../images/01/qual_matrix.png|Risk Matrix|300]]

The risk analyst would first determine the rating for likelihood as high, medium, or low.  Next, she will assess the level of impact using the same rating scheme.  Finally, she would cross reference these two measures on the risk matrix to evaluate the risk level.  For example, a "high" impact and "low" likelihood assessment yields a "medium" risk level.

The qualitative risk management methodology is easy to conceptually grasp with subjective measurements.  It offers some value as a tool to measure and communicate security risk levels; however, there are plenty of criticisms with the methodology.  Many professionals will find that the risk ratings are not granular enough, or they may find that the measurements of likelihood or impact are not scalar since qualitative values cannot be sensibly added or subtracted together (what does Low + Medium equal?).  Regardless of its shortcomings, it is a common approach to measuring and discussing security risk.
### Basic Quantitative Risk Management
A quantitative and slightly more sophisticated approach to measuring security risk estimates the *annual loss expectancy* by multiplying a *single loss expectancy* by the estimated *annual rate of occurrence*.  The single loss expectancy is determined by multiplying the estimated *asset value* by an *exposure factor*.  Lastly, the *asset value* is calculated by the number of records times the unit breach cost. 

>$AnnualLossExpectancy = SingleLossExpectancy * AnnualRateOfOccurrence$
>$SingleLossExpectancy = AssetValue * ExposureFactor$
>$AssetValue = Records*UnitCost$

The following scenario illustrates the use of this basic quantitative risk measurement:

> A database has 100,000 customer records.  Each record is estimated to cost \$5 in a breach.  The asset value of the database is therefore \$500,000 ($100,000 * \$5 = \$500,000$). If the database were breached, only half the data would be exposed because it is in plain text - while the other half is encrypted - making the exposure factor equal to 0.5.  The asset value of \$500,000 times the exposure factor of 0.5 produces a single loss expectancy of \$250,000 ($\$500,000 * 0.5 = \$250,000$).  Using industry reports, risk managers have determined that companies suffer database breaches at a rate of 5% which can be used as the annual rate of occurrence.  Multiplying the single loss expectancy of \$250,000 by the annual rate of occurrence 5% gives the annual loss expectancy of \$12,500 ($\$250,000*0.05=\$12,500$).

Using the above calculations, a security risk manager can estimate that the business has a $12,500 risk.  That risk manager will carry out similar estimates and calculations for all assets, summing the results to produce a final risk calculation in dollar terms.  Translating risk into dollars treats the information in a form all business managers can understand since they all understand costs.  This measurement taken over time can also identify the trend and direction of risk moving up or down.  The basic quantitative risk practice is considered more accurate than the qualitative method previously discussed.  However, it assumes a static likelihood while the real world may have more dynamic probability of occurrences.
### Advanced Quantitative Risk Management
Mature risk management functions or security departments may elect to use advanced quantitative risk methods to measure risk.  Basic quantitative measurements use a static likelihood value while advanced methods use a probabilistic model.  A risk manager will list risks and assign each one a probability value between 0 and 1 (for example 0.3).  Next, each risk will be assigned a lower and upper bound loss range to some confidence interval such as 90%.  You may be wondering how the 90% confidence interval of loss ranges are determined.  It could be as simple as surveying 10 professionals and obtaining their educated opinion of what a loss may be.  Then remove the highest and lowest estimate of the 10 or average their values.  Finally, the risk manager will calculate the annual expected loss using a calculation of random probability and loss value from a normal distribution.  This can be accomplished using Microsoft Excel's `norminv` function and summing all risk values calculated, as illustrated in the following figure.

![[../images/01/adv_quant_table.png|Advanced Quantitative Risk Calculations|600]]

There are fair criticisms of this risk calculation method, such as relying on estimates from individuals and the use of a normal distribution for the convenience of easier computations.  Real world observations would be ideal over subjective estimates and have the additional benefit of providing the actual distribution to be fitted.  However, such accurate data probably does not exist in a manner that can be consumed.  I highly recommend Douglas W. Hubbard's book "How to Measure Anything In Cybersecurity Risk" if you have further interest in security risk management.

![[../images/01/book_cover_risk.png|Quantitative Risk Measurement Recommended Reading|250]]
### Security Control Types
After risks are identified and measured, a risk department can prioritize how they are managed through treatment planning using a few control types.  *Administrative* controls include artefacts like policies, procedures, and written job duties.  Another popular administrative control is a review, such as the access review mentioned earlier in this chapter.  The *physical* control type has a tangible form such as a door with a deadbolt lock.  Finally, *technical* controls may be digital such as the technology that implements checking username and password combinations before granting access to data.  Each type of control will also have some security effect that is covered in the next section.
### Security Control Effect
Each control identified will naturally have one of the following effects:

| Effect       | Description                          | Example                          |
| ------------ | ------------------------------------ | -------------------------------- |
| Preventative | Forestall the risk from occurring    | Data Encryption                  |
| Detective    | Identify the occurrence of the risk  | Intrusion Detection System (IDS) |
| Deterrent    | Dissuade the risk from happening     | Flood Lights                     |
| Corrective   | Fix the impact of the risk           | System Auto-Restoration          |
| Compensate   | Indirectly control the risk          | Account Monitoring               |
| Transfer     | Impose the risk onto another entity. | Insurance                        |
| Avoid        | Withdraw from the risk               | Disconnect Internet              |
A risk can, and probably should, have more than one control with a diverse set of effects to ensure maximum security.  For instance, using multiple controls that both prevent and detect a given risk is a common observation.
### Risk Mitigation Considerations
Control types and control effects are not the only considerations when examining what controls to implement.  Security managers need to assess the strength of a control under consideration.  A weak control will not fully accomplish its goal, whereas a strong control could.  The cost of a control must also be carefully considered as you would not want to spend more on a control than the cost of the realized risk!  Another factor for consideration is the time for implementation.  It is common for a security department to purchase a solution and underestimate the amount of effort it takes to implement it.  In fact, the term *shelfware* has stemmed from company's buying solutions and never getting around to implementing them.  Finally, once all these factors are assessed, a decision can be made by management for the adoption or rejection of a control.
## Compliance
Organizations are often under obligations to ensure security by regulators, customers, and stakeholders.  Jurisdiction plays a large part when determining the legal security requirements to which an organization is subjected.  Customers expect their data to be secured and require defined confidentiality and security practices within vendor agreements and contracts.  Other entities, such as the board of directors, owners, and third parties, expect security and they may require adherence to industry security standards.  The collection of security requirements and its adherence by an organization from all these groups, is known as *compliance*.  Security requirements are usually documented, with varying degrees of obligation, in the following compliance types:

![[../images/01/compliance_pyramid.png|Compliance Pyramid of Obligation|300]]

Compliance requirements at the top of the pyramid have a higher degree of obligation as violation of the rules could result in an organization, or individual, being prosecuted by law enforcement or be assessed civil monetary penalties.  Guidance may place somewhere in the middle as it is often included as legal requirements in contracts between entities.  Violation of these agreements may result in the termination of a relationship which could lead to financial costs through loss of revenue or penalties.  Finally, policies have the lowest obligation as they can be changed by the organization at will, and their violation usually only results in employee disciplinary actions, such as being terminated.
### Laws and Regulations
There are several laws and regulations in the United States and elsewhere in the world.  The United States Code (USC) is a collection of federal statutes created by Congress and signed into law by the President.  Being found guilty of violating the law may result in penalties, such as fines and incarceration.  Laws can be enacted at the state and federal levels and their application depends on jurisdiction.  Most organizations will comply with the laws that impose the most restrictions to ensure compliance with all laws and for the sake of operational consistency.  Among other things, laws govern the way business may be conducted in the United States and have explicit requirements for security and data privacy.  The following list outlines some popular federal laws in the United States that have some security requirement expected of organizations:

- **Family Educational Rights and Privacy Act (FERPA)** - establishes the secure protection of student records;
- **Gramm-Leach-Bliley Act (GLBA)** - establishes privacy rights and requires financial institutions secure their customers' information;
- **Federal Information Security Management Act (FISMA)** - mandates security standards to protect government information systems;
- **Health Insurance Portability and Accountability Act (HIPAA)** - requires the protection of patient health information by the health care industry; 
- **Sarbanes-Oxley Act (SOX)** - implies requirements for information security standards to protect financial data by publicly traded companies.

Other countries also have laws that govern information security practices of organizations.  A popular law, **General Data Protection Regulation (GDPR)** in the European Union, establishes that organizations must adhere to privacy standards covering EU citizens' data and its security.  A US company conducting business in the EU, that meets the size threshold and collects EU citizen data, must follow this law or otherwise be fined significant amounts of money.  At the time of this writing, the current record for the largest fine by the GDPR is held by Meta in 2022 for $1.3 billion.

States also pass laws that affect security requirements of entities doing business within their borders.  The **California Consumer Privacy Act (CCPA)** and the **New York State Department of Financial Services (NYDFS) Cybersecurity Regulation (23 NYCRR 500)** are well known state laws that set privacy standards and cybersecurity requirements for organizations operating in their jurisdiction that reach eligibility criteria.

The USC establishes high level requirements and outlines who and how they are enforced.  The law will declare what regulatory body of the executive branch enforces it and grants the regulator additional powers such as defining regulations that enforce the law.  Formal regulations are written as part of the Code of Federal Regulations (CFR) developed outside of the legislature by federal agencies.  Therefore, each law described above has a regulator that establishes additional rules for organizations to follow.

A GRC professional will read these laws and regulations and seek to ensure their organization is compliant by applying the required controls.  He will work with lawyers, regulators, and operational business managers to ensure compliance of various legal requirements.  One approach to organizing this effort is by mapping each requirement of every law and regulation to a security control.  Once mapped, they collect evidence of the control that demonstrates legal compliance.  Such evidence is often requested during audits or examinations by third parties.
### Frameworks and Guidelines
Next in the compliance stack are frameworks and guidelines which are produced by industry organizations, non-regulatory government agencies, and even regulators.  They can also be stipulated within agreements between organizations, their customers, or their vendors.  The following list outlines common frameworks and guidelines security professionals encounter.

- **Center for Internet Security (CIS)** - a non-profit that publishes internet security standards;
- **National Institute of Standards and Technology (NIST) 800-53** - a non-regulatory government agency special publication describing security and privacy controls to achieve compliance with the Federal Information Security Management Act (FISMA).  Any government agency, their contractors, or their vendors must demonstrate compliance with FISMA;
- **Federal Risk and Authorization Management Program (FedRAMP)** - federal program prescribing the security standards of cloud-based information systems;
- **Payment Card Industry Data Security Standards (PCI/DSS)** - created by the Payment Card Industry Security Standards Council (PCI SSC), with members including Visa and Mastercard,  establishes security requirements for credit card merchants.  Companies that violate this standard may have their credit card processing rights revoked by the major credit card companies;
- **Federal Financial Institutions Examination Council (FFIEC)** - maintained by a consortium of financial regulators and outlines security standards expected of financial institutions; and
- **Cloud Security Alliance (CSA)** - non-profit which has standardized cloud security.

As guidelines are not legally binding by themselves, violations do not cause legal or regulatory enforcement actions even if the guideline was written by a regulator.  The process of publishing a law or regulation is time consuming and often fails, therefore, regulators use the guideline process to instruct regulated entities how to act. 
### Audit
Business customers typically do not trust an organization's security measures when handling or storing their sensitive data.  These customers will demand the organization prove that security controls are implemented and effective.  This process is called *vendor management due diligence* and is a critical component of business-to-business transactions.  As an organization grows its customer base, it may find it increasingly more difficult to prove security compliance at scale.  Therefore, an organization may seek a third-party certification that attests to the existence and functioning of security controls.  Having such a certification streamlines the operational burden of fielding customer inquiries and would otherwise require the organization to be fully audited directly by each of their customers.  **Service Organization Control Type 2 (SOC 2)** and the **International Organization for Standardization (ISO) 27001** are the two most common certifications organizations obtain.

The SOC 2 is conducted by a licensed certified public accountant (CPA) and is widely used in the United States.  There also exists a SOC 1, which is used to demonstrate financial controls (not security) and a SOC 3, which is a public version of the SOC 2.  The SOC 2 is a written report (usually 50-100 pages) that describes the organization's structure, customer security responsibilities, and the security controls being assessed.  The controls themselves are chosen by the organization and verified by the auditor to be aligned with the *Trust Services Criteria (TSC)*.  The auditor then renders an opinion on the effectiveness of the controls.  The SOC 2 is further subdivided by an additional layer of types: *type 1* and *type 2*, not to be confused with a SOC 1 and SOC 2.  A SOC 2 Type 1 report is a moment in time evaluation of the existence of a control and a SOC 2 Type 2 is an assessment of that control over a six months to one year time period.

![[../images/01/SOC2.png|SOC 2 Badge|150]]

Non-US and international companies usually achieve an ISO 27001 certification as it is recognized globally.  An organization will hire an accredited body to conduct the audit of the *information security management system (ISMS)*.  The auditor follows a strict listing of controls and tests them for effectiveness.  The auditor provides a report to the management of the company and a certificate to share with external parties proving compliance.

![[../images/01/iso_27001.png|ISO 27001 Badge|150]]

In both types of audits referenced here, the reviews are reconducted every 6 months to 1 year depending on the engagement.  Auditors perform tests by selecting a random sampling of a population related to a control and by verifying system records that prove compliance to that control.  For example, a common security control is to revoke a terminated employee's system access within 24 hours.  An auditor will request a list of all the terminated employees over a time period and then request records of their termination date and access removal.  System reports and screenshots are the preferred type of evidence collected.  Any discrepancies are documented as exceptions or findings and could jeopardize the overall status of compliance for that organization.
## Business Continuity Planning and Disaster Recovery
Information systems maintaining their availability is a component of the CIA triad covered earlier in the chapter.  This level of assurance requires careful planning, design, and testing of systems.  No system is impervious to unplanned downtime.  Measures must be taken that address what to do if there is an outage.  Such efforts are referred to as **Business Continuity Planning (BCP)** and **Disaster Recovery (DR)** where managers conduct **risk assessments** and **business impact assessments** to determine how a system could fail.  These assessments also identify an organization's tolerance for how long a system can remain unavailable.  Subsequentially, disaster recovery plans to restore the normal operation of systems are drafted and tested.
### Risk Assessment
There are a few categories of threats to the availability of information systems used within risk assessments.  The categories of threats are *natural*, *technical*, and *people*.  Natural threats include disasters such as earthquakes, floods, and tornadoes.  The physical placement of systems should consider locations that are susceptible to natural threats.  For example, there is a higher chance of an earthquake in the California Bay Area while there is minimal chance of a tornado.  Another threat to the availability of systems is technical, such as when the content delivery network (CDN) provider Cloudflare suffered a material internet outage for customers due to a border gateway protocol (BGP) misconfiguration. [^1]  Cybersecurity incidents can also cause technical outages.  For example, a ransomware attack could cause information systems to go offline.  The last available risk to consider during a risk assessment is from people.  This risk can arise from purposeful or accidental actions made by individuals.

> [!story] Story - Office Outage
> One time I was decommissioning a network rack that spanned multiple suites in an office building and clipped all the ethernet wires in the patch panel.  One of Ethernet wires provided internet to one of the office suites that was not supposed to be decommissioned.  This action caused an internet outage for the employees working in the suite and the ISP dispatched a technician to investigate the outage.

The BCP/DR risk assessment is often prepared by operations and technical managers jointly.  It is a written document, such as a spreadsheet, updated frequently or at least annually.  Its objective is to define the availability risks faced to information systems and business operations by identifying what could go wrong.  The risk assessment usually consists of a list of risks that fall under the risk categories natural, technical, and people.  The next step in the BCP/DR process is to identify the impact a risk may have on the business.
### Business Impact Assessment
With a risk assessment completed, the business needs to identify the level of impact and inter-dependency business units have on technology.  The **business impact assessment (BIA)** is a written document, typically another spreadsheet, that lists each business unit and information systems it depends on.  The risk analyst will interview department leads to determine how they would be affected should an information system be unavailable.  The analyst collects this information and rates each department and information system with a priority.  For example, in the restaurant industry, if the credit card network or equipment becomes unavailable, the business would be adversely affected because it could not process payments.  Although less than ideal, the restaurant could still conduct business using cash or by collecting card information and running charges later.  The restaurant would be adversely affected but not out of commission, so an appropriate BIA rating for the front of house operation and the credit card network may only be a *medium*.

During the BIA process, the analyst would attempt to measure various thresholds of tolerance and expectations which could also inform the level of priority needed.  This is helpful in the event of an outage of several systems and having a firm understanding which systems to prioritize first - especially if one system depends on another system.  Using the previous example, the restaurant credit card system depends on availability of electricity to the building.  The back of the house depends on electricity to run the lights needed for the cooks to see what they are doing.  Without electricity the restaurant would have to shut down, and therefore a disaster recovery team should focus on restoring the electricity before attempting to restore the credit card system.
### Measures
Time is measured in numerous ways to enrich the BIA.  These metrics are written in hours, days, or months for each business unit and information system.  One such measurement is the **Recovery Point Objective (RPO)** which instructs how much data needs to be restored.  Imagine a database that maintains customer sales leads.  Losing this data would be harmful to the business, but it might only cause the loss of potential future sales.  An appropriate RPO, in this case, is a daily backup.  The business could tolerate the loss of one day's worth of data.  Compare this to a bank's database that stores a high volume of customer financial transactions.  The loss of even one minute of this data could cost the bank millions of dollars.  A real-time backup, or database replication, may be required and an RPO of 1 second is all the bank could tolerate.

A business must also determine how long a system can be down for before the business is severely impacted, or will go out of business permanently.  **Maximum Tolerable Downtime (MTD)** attempts to quantify this threshold.  For example, an accounts payable system used for paying vendors and employees may be determined to have an MTD of one month.  After which vendors will begin terminating contracts and employees will quit due to not receiving payments, which would be catastrophic to the business.  If this system was down for one day or one week, it would cause only a minor disruption to the business.

Armed with the knowledge of the RPO and MTD, the analyst can work with business and system administrators on how long it will take to get a system back up and running with a metric called **Recovery Time Objective (RTO)**.  Ideally, the RTO is less than the MTD. If the RTO is greater than the MTD, the business will be at great risk should an outage occur.  In such cases, the business should seek to reduce risk by decreasing its RTO or finding ways to extend its MTD.  A complete BIA with RPO, MTD, and RTO might look something like the following example:

![[../images/01/bia.png|Business Impact Analysis|600]]

### BCP/DR Plan
After the risk assessment and BIA process is completed, the business can develop a plan on how to address the risk of an outage for a given business unit or information system.  The BCP/DR plan is a written document that describes the roles and responsibilities of all parties needed to recovery systems and operations.  It will describe who is responsible for communication with the employees of an organization and how to handle customer inquiries.  It will include instructions on how to address anticipated events, such as offsite meeting locations and alternative procedures.  The document usually includes an out-of-band call tree if phone systems become unavailable.  Key personnel should print a physical copy of the BCP/DR plan and maintain it at their homes in case of an office fire or computer outage, making digital copies unavailable.  Some BCP/DR plans go as far as forbidding the chief executive officer (CEO) and the chief financial officer (CFO) from sharing the same flight due to the risk of a plane crash.  The plan would also establish communication and training strategies for participating members of the organization so that everyone knows what to do in the event of an outage.  The plan will prescribe how events should be documented and may include template reports to ensure all relevant information is consistently and comprehensively collected.

Once created, the plan should be regularly tested using *tabletop exercises*.  During these exercises, key members work together in a conference room under the pretense of an outage and describe how they would handle a given scenario.  Another form of testing is to simulate disaster events by removing system components or recovering systems while assessing the performance of the plan.  A well-planned test will have defined objectives whose performance will be measured to determine the successfulness of the response actions.  Being prepared goes a long way when events come to fruition.  These efforts could mean the difference in a company's survival.
## Data Classification
Not all information is worth protecting; some information may require more protective controls than others.  The process of identifying, labeling, and assigning required controls to information is known as **data classification**.  Information, and the systems that process and store them, are labeled to indicate who has access rights and what level of protection is necessary.  This labeling, or classification, varies between the private and public sectors.  The following graphic illustrates two overly simplified data classification schemes.

![[../images/01/data_classification.png|Data Classification Schemes|500]]

Typically, there are at least three levels of classification, with the most open level available for anyone's permitted use.  An example of this *public* or *unclassified* information is the splash page of a website available on the internet to anonymous users.  Information on such a site is easily accessible by anyone.  The next tier represents valuable information that should not be made public but may be available to an audience that needs to know.  Sometimes referred to as *internal* or *secret*, this information requires security controls that ensure access is only made to authorized persons.  The most sensitive data classification is *confidential* or *top secret* tier.  This data is highly restricted and must have the highest levels of security controls.  A *hardware security module (HSM)* system, which stores encrypted secrets, serves as an example of an information system or data that reaches this level of classification.
## Identity Access Management
System administrators are required to maintain control over access to networks and systems.  This is accomplished through **identity and access management (IAM)** which has developed into a defined subfield of information security over the last several years.  It is common to see companies hiring explicitly for security professionals with IAM experience, and some larger organizations may hire individuals to only manage IAM.  The responsibility for ensuring IAM controls falls on both system administrators (or admins) and security professionals.  In a general sense, admins grant and revoke access to systems while security professionals ensure access is securely maintained through access reviews.

A system that ensures IAM practices will establish **authentication, authorization, and accounting (AAA)** capabilities.  The authentication process confirms the identity of the entity requesting access to a system, whereas authorization verifies an authenticated entity is permitted to perform actions on that system.  When accounts interact with the system, an events record or log, known as accounting, should be created.  The accounting arm of AAA should log authentication and authorization events at a minimum.  Additional log entries in robust systems will include the actions made by each account, especially over sensitive features of the system like creating and modifying other accounts.

> [!tip] Tip - IAM Lingo
> The shorthand for authentication is *authn* and for authorization is *authz*.

### Identity and Factors
The authentication phase of IAM's AAA requires an **identity** and a **factor** to validate a user.  The identity of a *service principal* is usually not treated as a secret and can often be found publicly.  Examples of an identity include usernames, or a physical badge worn on a lanyard.  A factor is *something you know*, *something you have*, or *something you are*.  The most common example of a factor is a password (know), hardware token (have), or biometric scan (are).  The process of presenting the identity and factor combination to the system that makes the validity decision is called authentication.

Passwords are wrought with deficiencies which can make systems less secure, as anyone that knows the password could masquerade as that entity.  Passwords can be leaked or guessed in several ways that we will explore later in this book.  Because of their weakness, many secure systems require *multi-factor authentication* that includes at least two different factor types (know, have, are).  For example, during the authentication process, an entity must provide their username (identity), password (factor 1 - know) AND a hardware token value (factor 2 - have).

> [!warning] Warning - Common MFA Mistake
> A common mistake when determining the use of MFA is confusing the use of two of the same factors as MFA.  For instance, presenting a password and a pin is not MFA because both factors are something you know.  True MFA systems require the use of different factor types!
### Permissions
After an entity is authenticated, it will perform actions against a system.  Authorization determines if the authenticated entity is allowed to perform requested actions.  **Permissions**, which are allowed actions for an entity, are maintained within the system and assessed for each request.  There are many actions that can be conducted by the entity, but most conform to *reading*, *writing*, and *executing* and abbreviated as (RWX).  We will explore some common methods on how systems determine permissions in the next section.

There are two principles that should be followed when assigning or assessing entity permissions.  The **need to know principle** evaluates if the entity has a reasonable and confirmed use case for the system or its data.  An individual should not have access to a system if they do not have a justifiable reason, regardless of that individual's standing in the organization.  This often arises when granting access to an executive at a company.  Just because an executive is responsible for the organization does not mean they should have root access on a server.  If they are granted access when they do not need it, an undue exposure to system breach could be manifested should that executive's account every be compromised.  After determining if an entity should have access to the system, the administrator must apply permissions to the account, determining the level of access the entity will have.  Maintaining just enough access for the entity's use case is known as the **least privileged principle**.  Continuing with our executive example, perhaps that executive needs access to the server to download a specific report.  Providing root access to that server gives excessive permissions which violates the least privileged principle.  Perhaps the executive only needs "read" access to a specific folder or files on the server.  Granting only that narrow access will achieve the least privileged goal.
### Access Control
![[../images/01/acl.png|Azure ACL|400]]
There are several architectures to map entities with permissions and control access within information systems.  Engineers that design systems must consider the logic of how they authenticate and authorize access.  A common design to assign who can access what in a system is the **access control list (ACL)**.  The ACL lists each entity and the permission they have for an object in that system.  The image above is a screenshot taken from Microsoft Azure demonstrating an ACL for the "/myDirectory" object.  The object lists each principal's permissions on that object.

The ACL is managed by the object's owner, who can assign which service principals can perform actions on the object.  This type of ACL where the owner of the object administers control is known as a **discretionary access control list (DACL)**.  There are other variants of access control to consider, such as **mandatory access control (MAC)** in which another system maintains what users can access data and systems under different data classifications.  Each entity is assigned a *clearance level* and information systems are labeled with a *data classification*.  When an entity requests data from the system, the clearance level and the classification label are checked against a control list to allow or block the request.

![[../images/01/mac.png|Mandatory Access Control|550]]

An information system with thousands of service principals and millions of objects would become unmanageable.  Easing the burden of administering access promotes a more secure environment as it can streamline access decisions making a system less complicated.  One strategy to organize access is through **role-based access control (RBAC)** in which system administrators can create roles of permission sets.  Once the role is created and permissions assigned, the administrator adds users to the role who inherit the permissions.  This simplifies reviews of permissions much easier, as similar user groups will have consistent permissions assigned.
### Managing IAM
Organizations must establish processes to ensure effective access management on their information systems.  The system administrator and security professional have important roles that support IAM system management.  Administrators are responsible for *provisioning*, *updating*, *reviewing* and *revoking* access to systems.  Human resource departments typically supply administrators with events, such as employee onboarding or termination, and information, such as user details like name and job type.  The administrator will be alerted to this event and use the information provided to configure access to systems.  The administrator is responsible for ensuring the principles of least privilege and need to know is applied.  She must challenge any requests for access that do not seem appropriate or lack detail to make an informed decision.

It is common for a service principal's use case to change overtime.  This usually results in a user having more access than what is needed and is commonly referred to as *access drift*.  Identifying and correcting these issues requires frequent reviews and use case validations.  It can sometimes be contentious when removing permissions of a long-standing user, as they have grown accustomed to the higher level of access.  This resistance sometimes deters change, and it is important for a security professional to insist, when appropriate.  Another common issue is when the deprovisioning process fails to notify a system administrator to remove access.  If an employee is terminated, someone must notify the admin to remove that terminated employee's access, otherwise it will persist past employment.  Failing to revoke access timely exposes the organization to unauthorized access by a potentially disgruntled former employee.  In 2021, a New York Credit Union lost high volumes of financial data several days after terminating an employee.  The disgruntled ex-employee discovered they still had access to sensitive information systems and as an act of revenge, deleted important data. [^2]

<br>

 >[!info] Info - Advanced IAM
 >We covered the basics of IAM in this chapter, but there is much more to learn.  Interested readers are encouraged to research more about advanced IAM topics such as OAuth and SAML protocols, OpenID Connect (OIDC), Single Sign-On (SSO), and systems for cross-domain identity management (SCIM).

## Summary
This chapter introduced foundational elements of an information security program.  It included how organizations identify, assess, and manage risks to their data and systems. The CIA triad (confidentiality, integrity, availability) was introduced as the guiding model for controls.  We also walked through compliance requirements from laws and regulations to frameworks and standards like SOC 2 and ISO 27001, and examined how governance, risk, and compliance (GRC) professionals map legal requirements to security controls.  The chapter described the roles and responsibilities of key positions within a security department and how policies and procedures build security culture within an organization.  Topics covering identity and access management to control access to systems and networks was highlighted alongside the importance of managing availability risk through business continuity and disaster recovery practices.

>[!terms] Key Terms
>**Access Control List (ACL)** -  A data structure that explicitly maps entities to their allowed permissions on a specific object.  
>
>**Actions on Objectives** - The final attack steps in which the adversary achieves their goals, such as data exfiltration or system disruption.  
>
>**Authentication, Authorization, and Accounting (AAA)** - The framework for confirming identity, granting permissions, and logging user activity.  
>
> **Availability** - A goal that information and systems are accessible when needed. 
> 
> **Business Continuity Planning (BCP)** - Developed procedures to ensure critical business functions can continue functioning during and after a disruption.  
> 
> **Business Impact Assessment (BIA)** - The exercise of quantifying the operational and financial effects of business process interruptions.  
> 
> **California Consumer Privacy Act (CCPA)** - A state law granting California residents rights over their personal information and mandating vendor data protection practices.  
> 
> **Center for Internet Security (CIS)** - A nonprofit organization that publishes consensus-based best-practice benchmarks and controls for securing IT systems.  
> 
> **CIA Triad** - A foundational information security model that is defined by three core objectives of protecting information: confidentiality, integrity, and availability.  
> 
> **Cloud Security Alliance (CSA)** - A nonprofit that develops best practices and frameworks for securing cloud computing environments.  
> 
> **Command & Control** - The channel through which an attacker remotely issues instructions and receives data from compromised systems.  
> 
> **Confidentiality** - Ensures that information is accessible only to authorized parties and remains secure from unauthorized access.  
> 
> **Control** - A safeguard or countermeasure implemented to mitigate risk by preventing, detecting, or correcting security incidents.  
> 
> **Data Classification** - The process of categorizing information based on its sensitivity and assigning appropriate protection controls.  
> 
> **Defense in Depth** - A security strategy that layers multiple controls across people, processes, and technologies to protect information assets and systems.  
> 
> **Delivery** - The phase in which the attacker transmits the weaponized payload to the target through channels such as email, web, or USB.  
> 
> **Disaster Recovery (DR)** - The practice of restoring IT systems and operations following a significant disruption or outage.  
> 
> **Discretionary Access Control List (DACL)** - An ACL managed by the object owner who decides which entities may access the object.  
> 
> **Exploit or Exploitation** - The method or technique used to leverage a vulnerability in order to deliver a payload or achieve unauthorized access.  
> 
> **Factor** - The type of credential (something you know, have, or are) presented during authentication.
> 
> **Family Educational Rights and Privacy Act (FERPA)** - A U.S. federal law that mandates the protection and privacy of student education records.  
> 
> **Federal Financial Institutions Examination Council (FFIEC)** - A consortium of U.S. financial regulators that issues guidance and examination procedures for IT security in banking.  
> 
> **Federal Information Security Management Act (FISMA)** - U.S. legislation that enforces security standards for federal information systems and their contractors.  
> 
> **Federal Risk and Authorization Management Program (FedRAMP)** - A U.S. government program that standardizes security assessment and authorization processes for cloud services.  
> 
> **General Data Protection Regulation (GDPR)** - An EU regulation that imposes stringent data protection and privacy requirements for processing the personal data of EU citizens.  
> 
> **Gramm-Leach-Bliley Act (GLBA)** - A U.S. law requiring financial institutions to implement safeguards for customer nonpublic personal information.  
> 
> **Health Insurance Portability and Accountability Act (HIPAA)** - A U.S. law that sets national standards for protecting electronic patient health information.  
> 
> **Identity and Access Management (IAM)** - The discipline of defining and enforcing digital identities and access rights across systems.  
> 
> **Identity** - The unique identifier (such as a username) used to represent an entity within a system.
> 
> **Installation** - The stage where malware or backdoors are planted on the compromised system to maintain persistence.
> 
> **Integrity** - Guarantees that information remains accurate and unaltered except by authorized actions.
> 
> **International Organization for Standardization (ISO) 27001** - The global standard specifying requirements for establishing and maintaining an Information Security Management System (ISMS).
> 
> **Least Privileged Principle** - The practice of granting entities the minimum permissions required in a system to accomplish their tasks.
> 
> **Mandatory Access Control (MAC)** - A policy model where access is enforced by the system based on labels and clearances rather than owner discretion.
> 
> **Maximum Tolerable Downtime (MTD)** - The longest duration a system or process can remain unavailable before causing unacceptable business harm.  
> 
> **National Institute of Standards and Technology (NIST) 800-53** - A NIST special publication that catalogs security and privacy controls for federal information systems.  
> 
> **Need to Know Principle** - The tenet that an entity should only access information or systems when there is a requirement to do so and as part of their legitimate duties.  
> 
> **New York State Department of Financial Services (NYDFS) Cybersecurity Regulation (23 NYCRR 500)** - A set of rules requiring financial services firms in New York to establish cybersecurity programs and controls.  
> 
> **Payload** - The component of an attack that includes the harmful action or malicious code that will exploit a vulnerability.
> 
> **Payment Card Industry Data Security Standards (PCI/DSS)** - Industry-mandated requirements designed to protect cardholder data in payment processing environments.
> 
> **Permissions** - The actions an authenticated entity is allowed to perform on a system resource.
> 
> **Reconnaissance** - The initial phase of an attack lifecycle where the adversary gathers information about the target’s systems and defenses.
> 
> **Recovery Point Objective (RPO)** - The maximum tolerable period in which data might be lost after an outage, expressed as a point-in-time.
> 
> **Recovery Time Objective (RTO)** - The target time within which systems or processes must be restored following an outage.
> 
> **Risk Assessments** - Systematic evaluations of threats, vulnerabilities, and potential impacts to determine security risk levels.
> 
> **Risk** - The potential for loss or damage when a threat exploits a vulnerability in an information asset.
> 
> **Role-Based Access Control (RBAC)** - A model where permissions are assigned to roles and entities inherit those permissions by being members of roles.
> 
> **Sarbanes-Oxley Act (SOX)** - A U.S. statute that enforces financial reporting integrity and internal control requirements for publicly traded companies.
> 
> **Service Organization Control Type 2 (SOC 2)** - An audit report by a licensed CPA assessing the operational effectiveness of an organization’s controls against Trust Services Criteria over time.
>  
> **Threat Actors** - Individuals or groups—such as insiders, cybercriminals, hacktivists, or nation-states—who carry out attacks against information systems.
> 
> **Threat** - Any circumstance or event with the potential to adversely impact information systems through unauthorized access, disruption, or destruction.
> 
> **Vulnerability** - A weakness in a system, process, or design that can be exploited by a threat actor.
> 
> **Weaponization** - The process of coupling exploit code with a payload to create a deliverable malicious artifact.

## Exercises
Each chapter of this book will include lab exercises on the covered topics.  Readers are encouraged to complete the labs to gain practical experience and to demonstrate a deeper understanding of the material covered.  Many individuals in the security community contribute to the body of security knowledge through blog posts, how-to videos, and capture the flag challenges.  Becoming proficient in security requires the ability to set up scenarios in a lab environment and experiment with systems.  The labs in this book will use the infrastructure established in the following exercises.

> [!exercise] Exercise 1.1 - Install VirtualBox
> In this lab, you will install VirtualBox on your host machine to support three virtual machines (VMs) that will be used as test environments and support future lab coursework.
>#### Step 1 - Download and Install VirtualBox
>![[../images/01/lab_01_task_manager.png|Task Manager|400]]
>1. Ensure your processor supports virtualization that is enabled in the BIOS/UEFI.  In Windows, this can be done using the Task Manager.  You must enable virtualization.  You will not be able to proceed with the course if your CPU does not support virtualization!
>2. Navigate to [https://www.oracle.com/virtualization/technologies/vm/downloads/virtualbox-downloads.html](https://www.oracle.com/virtualization/technologies/vm/downloads/virtualbox-downloads.html) 
>3. Select Installer (Windows, Mac OS X, Linux):
> ![[../images/01/lab_02_vbox_download.png|VirtualBox Download page|400]]
> 4. Run the installer, follow the prompts, default settings should be fine.  Launch VirtualBox:
> ![[../images/01/lab_03_vbox_installed.png|VirtualBox Startup Window|300]]


> [!exercise] Exercise 1.2 - Install Kali Virtual Machine
> After VirtualBox is installed on your host machine, you will install a Kali Linux VM.  Kali is a Debian distribution maintained by Offensive Security.  It comes preinstalled with many security tools, lists, and apt repositories that we will be using throughout the course.  You will download the ISO image from the Kali website and manually install the operating system as a VM.  Once installation is complete, you will install the VirtualBox guest additions and configure the VM to share resources with your host computer.
> 
> #### Step 1 - Download and Setup Kali VM
> 5. Navigate to [https://www.kali.org/get-kali/#kali-installer-images](https://www.kali.org/get-kali/#kali-installer-images)
> 6. Select the download button for the 64-bit Installer image:
> ![[../images/01/lab_04_kali_dowload.png|Kali Linux Download Page|200]]
> 7. With the ISO for Kali fully downloaded (~10-20 minutes depending on internet speeds), navigate to the running VirtualBox application and select the “New” button:
> ![[../images/01/lab_03_vbox_installed.png|VirtualBox Startup Windows|300]]
> 8. The VirtualBox "Create Virtual Machine" wizard should appear.  Within the wizard, name the VM “kali” and select the Kali ISO location downloaded in the previous steps.  Then press the Next button.
> 9. Within the "Hardware" wizard page, supply the VM with 4GBs memory and 2 processors (note, these settings can be increased or decreased later if needed) then press Next.
> 10. On the "Virtual Hard disk" page, select "Create a Virtual Hard Disk Now", change the "Disk Size" to 30GB and press the Next button.
> 11. Within the "Summary" wizard page, review the settings and press Finish.
> 12. With the “kali” VM selected, press the “Start” button to launch the VM in a new window:
> ![[../images/01/lab_05_kali_started.png|Kali Started|400]]
> #### Step 2 - Install Kali Operating System
> 13. Select “Graphical Install” within the VM window and hit enter to launch the operating system installation wizard.
> 14. The VM's installation wizard starts on the "Select a language" page.  Select the language "English" and press Continue.
> 15. While on the "Select your location" page, choose your location.  For example, "United States" and then press Continue.
> 16. On the "Configure the keyboard page, select keyboard layout American English and press Continue.
> 17. Allow the Kali installer to run and the wizard will eventually launch the "Configure the network" page.  Enter the hostname “kali” and press Continue.
> 18. On the second "Configure the network page", leave "Domain name" field empty and Continue.
> 19. Next, on the "Set up users and passwords" page, enter your name in the "Full name for the new user" field and press Continue.
> 20. From the second "Set up users and passwords" page, enter your name as the username in the "Username for your account" field and press Continue.
> 21. In the third "Set up users and passwords" page, enter a password in the "Choose a password for the new user" and the "Re-enter password to verify" fields.  Make sure you remember this password!  Press the Continue button to advance the installation.
> 22. In the next wizard page "Configure the clock", select your time zone and press Continue.
> 23. On the "Partition disks" page, allow a moment for the disks to be detected, then select the “Guided - use entire disk” option and press Continue.
> 24. From the second "Partition disks" page, select default partition and press Continue.
> 25. Within the third "Partition disks" page, select the “All files in one partition” option and press Continue.
> 26. In the fourth "Partition disks" page, select the “Finish partitioning and write changes to disk” to commit the partition changes and then press Continue.
> 27. On the fifth and last "Partition disks" page, select “Yes” to the "Write the changes to disks" question (note default option is no) and press Continue.
> 28. While in the "Software selection" window, wait for the system to install.  Then use the default software selections and press continue.
> 29. Once the software is installed, after waiting for ~25 minutes, the "Install the GRUB boot loader" window appears.  Select "Yes" and then press Continue.
> 30. Still on the "Install the GRUB boot loader" page, select the available device `/dev/sda` (not "Enter device manually") and press Continue to install the boot loader.
> 31. Wait some time for the installation to finish and the "Finish the installation" page will appear.  Press Continue to complete the installation.
> #### Step 3 - Configure Kali
> 32. The system will reboot and launch the login menu.  Enter the username and password used during installation.  If the VM boots to a black screen, you may need to increase the "Video Memory" of the VM.  Navigate to VirtualBox, select your VM, press Settings, choose Display from the navigation menu on the left, and then increase the Video Memory.
> ![[../images/01/lab_06_kali_login.png|Kali Login Screen|500]]
> 33. The system will log in and present the Kali desktop.  Right click in the desktop and select “Open Terminal Here” from the context dropdown menu.
> 34. With the terminal open, run the apt update command and then enter your password to update the system.
> `sudo apt update -y`
> 35. After updates have been installed, install the VirtualBox guest software using the following command. 
> ```
> sudo apt install -y --reinstall virtualbox-guest-x11
> ```
> ![[../images/01/lab_07_kali_update.png|Kali Terminal Update and Install|500]]
> After the guest software is installed, select the Devices menu, Drag and Drop, and then the Bidirectional option.
> ![[../images/01/lab_08_kali_drag_drop.png|VM Drag and Drop Setting|400]]
> Similarly, select the Devices menu, Shared Clipboard, and select the Bidirectional setting to enable copying clipboard values between the host and VM.
> 
> Return to the Kali terminal and reboot the VM using the following command.
> ```
> reboot
> ```
> Congratulations, you have successfully set up Kali in VirtualBox!  If you have adequate disk space (2x the recommended minimum) then you may consider taking a snapshot of the fresh installation in case you ever want/need to start with a clean install.


>[!exercise] Exercise 1.3 - Install Ubuntu Virtual Machine
> 
> We will use an Ubuntu VM throughout the course as a victim, server, or to illustrate secure configurations.  Ubuntu is another Debian distribution maintained by Conical and is one of the most popular Linux operating systems.  You will download an ISO image and install the system using the unattended installation feature.  Once completed, we will configure the VM to share resources with the host.
> #### Step 1 - Download and Set Up Ubuntu VM
> 37. Navigate to https://releases.ubuntu.com/22.04/ and download the Ubuntu version 22.0.4 image.
> 38. With the ISO for Ubuntu fully downloaded (~10-20 minutes depending on internet speeds), navigate to the running VirtualBox application and select the “New” button.
> 39. The VirtualBox "Create Virtual Machine" wizard will launch.  On the "Virtual machine Name and Operating System" page, enter "ubuntu" in the name field and select the Ubuntu ISO image you downloaded in the previous step.  Leave the "Skip Unattended Installation" checkbox UNCHECKED and press Next.
> 40. Within the "Unattended Guest OS Install Setup" page, change the username to your name, enter a password, and change the domain name to "lan".  Ensure the "Guest Additions" option is checked and press Next.
> 41. In the "Hardware" page, select a "Base Memory" of 4096MB and set "Processors" to 2 CPUs (these settings can be adjusted later if more/less resources are needed).
> 42. On the "Virtual Hard disk" page, choose the option "Disk Size" and set it to 35 GBs then press Next.
> 43. Review your settings on the "Summary" page and press "Finish" to complete the setup.
> #### Step 2 - Install Ubuntu OS
> 44. Observe the ubuntu VM has been configured and is running in the VirtualBox application.  Select the ubuntu entry and then the Show button to watch the installation progress.  The installation should take 20-30 minutes.
> ![[../images/01/lab_10_ubuntu_install.png|Ubuntu OS Auto Installation|650]]
> 45. Once installation is complete the VM will reboot to the login screen.  Login with the user account you setup in step 4.
> #### Step 3 - Set Up Ubuntu OS
> Like Kali, set up the shared clipboard and drag and drop VM settings.  Select Devices, Shared Clipboard, and choose Bidirectional.  Then select Devices, Drag and Drop, and choose Bidirectional.
> 
> Congratulations, you have successfully installed the Ubuntu VM on VirtualBox! If you have adequate disk space (2x the recommended minimum) then you may consider taking a snapshot of the fresh installation in case you ever want/need to start with a clean installation.


> [!exercise] Exercise 1.4 - Install Windows Virtual Machine
> The last VM we will be using in our lab environment is a Windows 10 machine.  Like Ubuntu, it will act as a victim, server, or be used to demonstrate secure configurations.  You will install an evaluation version so there is no need to purchase a license.  To obtain the ISO, you will download the Windows installation media tool to your host machine, configure the desired ISO, and download it.  You will then create a VM using this ISO and use the unattended installation feature.  After installation we will set up the ability to share resources between the host and the VM.
> #### Step 1 - Download the Windows ISO
> 46. Navigate to https://www.microsoft.com/en-us/software-download/windows10 and press the "Download Now" button under the "Create Windows 10 installation media" section.
> ![[../images/01/lab_11_win_download.png|Download Media Creation Tool|450]]
> 47. Open the Downloads folder and run the Media Creation Tool executable which will launch the "Windows 10 Setup" wizard in a new window.
> 48. Within the "Windows 10 Setup" window, accept the licensing and choose “Create installation media (USB flash drive, DVD, or ISO file) for another PC” option.
> 49. On the "Choose which media to use" page of the wizard, use the recommended options and select ISO file.
> ![[../images/01/lab_12_win_iso.png|Media Creation Tool ISO Selection|400]]
> 50. Select the location to save the ISO and the download will begin.  Select Finish once complete (no need to burn to DVD) and the download process should begin.  The download may take 10 to 20 minutes depending on your internet connection.
> #### Step 2 - Set Up the Windows VM
> 51. After the ISO for Windows download completes, navigate to the running VirtualBox application and select the “New” button which launches the VirtualBox "Create Virtual Machine" wizard in a new window.
> 52. On the "Virtual machine Name and Operating System" wizard page, enter "windows" in the "Name" field then navigate and select the ISO file downloaded from the Media Creation Tool in the "ISO Image" field.  Press the Next button to continue the configuration.
> 53. From the "Unattended Guest OS Install Setup" page, adjust the unattended install setup with your name as the username and a password of your choosing, set the "Doman Name" to lan, and check the "Guest Additions" option.  We will not be licensing Windows so do not worry about the Product Key; press the Next button.
> 54. Within the "Hardware" page, set the "Base Memory" to 4096 MB and set 2 processors.  Press the Next button to continue the configuration.
> 55. On the "Virtual Hard disk" page, select "Create a Virtual Hard Disk Now", enter 45 GB, and press Next.
> 56. Review the settings on the "Summary" page and press Finish if all looks correct to start the unattended operating system installation.
> ![[../images/01/lab_13_win_summary.png|Windows VM Summary|500]]
> #### Step 3 - Install Windows OS
> 57. Windows should take 20-30 minutes to install and can be monitored by selecting Show in VirtualBox on the running windows VM.
> ![[../images/01/lab_14_win_install.png|Windows VM Installation|500]]
> #### Step 4 - Set Up Windows OS
> 58. After the installation is complete, you will be automatically logged into the VM to the Windows desktop.  You may have to adjust the VirtualBox View settings and/or the Windows display settings for the best experience.  If your window does not show the file menu, try using VirtualBox shortcut keys to display (in Windows right CTRL + Home button). 
> 59. Like Kali and Ubuntu VMs, set up the shared clipboard and drag and drop VM settings. Select Devices, Shared Clipboard, and choose Bidirectional. Then select Devices, Drag and Drop, and choose Bidirectional.
> 
> Congratulations, you have successfully installed Windows in VirtualBox!  If you have adequate disk space (2x the recommended minimum) then you may consider taking a snapshot of the fresh installation in case you ever want/need to start from a clean installation.


[^1]: BGP Router Leak Causes Cloudflare and Amazon AWS Problems; By Lawrence Abrams; 2019; https://www.bleepingcomputer.com/news/technology/bgp-route-leak-causes-cloudflare-and-amazon-aws-problems/
[^2]: Fired NY credit union employee nukes 21GB of data in revenge; By Sergiu Gatlan; 2021; https://www.bleepingcomputer.com/news/security/fired-ny-credit-union-employee-nukes-21gb-of-data-in-revenge/