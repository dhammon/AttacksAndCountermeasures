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
7. Understand identity access management processes and control models; and
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

> [!info] Info - What is security risk?
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
Organizations are often under obligations to ensure security by regulators, customers, and stakeholders.  Jurisdiction plays are large part when determining the legal requirements an organization is under to provide security of information.  Customers expect their data is secure and establish contracts requiring confidentiality and security practices.  Other parties, such as board of directors, owners, and third parties expect security and may require adherence to industry security standards.  The collection of security requirements from all these entities, and proving adherence to them, is known as *compliance*.  There are varying degrees of obligations illustrated in the following graphic.
![[../images/01/compliance_pyramid.png|Compliance Pyramid of Obligation|300]]
Compliance requirements at the top of the pyramid have a higher degree of obligation as violation of the rules could result in an organization, or individual, being prosecuted by law enforcement or be assessed civil monetary penalties.  Guidance may place somewhere in the middle as it is often included as legal requirements in contracts between entities.  Violation of these agreements may result in the termination of a relationship which could cost an organization financially.  Finally, organization policies have the lowest obligation as can be changed by the organization at will and violation of policies usually result in employees being terminated.
### Laws and Regulations
There are several laws and regulations in the United States, and elsewhere in the world, and it is important to understand the difference.  In the US, the United States Code (USC) is a formal document created by legislative bodies and signed into law by executive powers.  Violating the law while being found guilty results in penalties such as fines and incarceration.  Laws can be enacted at the state and federal levels and applying the laws depends on jurisdiction.  Most organization apply the most strict laws to their operations for consistency sake.  Among other things, laws govern the way business may be conducted in the United States and have explicit requirements for security and data privacy.  The following list outlines some popular federal laws in the United States that have some security requirement expected on organizations:
- **Family Educational Rights and Privacy Act (FERPA)** - establishes the secure protection of student records;
- **Gramm-Leach-Bliley Act (GLBA)** - establishes privacy rights and requires financial institutions secure their customer's information;
- **Federal Information Security Management Act (FISMA)** - mandates security standards to protect government information systems;
- **Health Insurance Portability and Accounting Act (HIPAA)** - requires the protection of patient health information by the health care industry; and
- **Sarbanes-Oxley Act (SOX)** - outlines information security standards to protect financial data by publicly traded companies.

Other countries also have laws that govern information security practices of organizations.  A popular law, **General Data Protection Regulation (GDPR)** in the European Union, establishes that organizations must adhere to privacy standard for EU citizens data while ensure that data's security.  A US company conducting business in the EU, that meets the size threshold and collects EU citizen data, must follow this law and otherwise be fined significant amounts of money.  The current record for the largest fine by the GDPR is held by Meta in 2022 for $1.3 billion.

States also pass laws that affect security requirements of entities doing business within their borders.  The **California Consumer Privacy Act (CCPA**) and the **New York Cybersecurity Regulation (NYCRR)** are commonly referred to state laws that set privacy standards and cybersecurity standards depending on jurisdiction and eligibility criteria.

The USC establishes high level security requirements and outline who and how they are enforced.  The subject law will declare what regulatory body of the executive branch enforces the law and grants the regulator additional powers such as defining further regulations on applying the law.  The formal regulations are written as the Code of Federal Regulations (CFR) and are manifested outside the legislature.  Therefore, each of the laws described has a regulator that outlines more rules for compliance.

A GRC professional will read these laws and regulations and seek to ensure the are applied at their organization.  They will work with lawyers, regulators, and operational business managers to ensure compliance to the various legal requirements.  One approach to organizing this effort is by mapping each requirement of every law and regulation to a security control.  Once mapped, collect evidence of the adherence of that control which conveniently demonstrates legal compliance.
### Frameworks and Guidelines
Next in the compliance stack are frameworks and guidelines which are produced by industry organizations, non-regulatory government agencies, and even regulators.  The following list outlines common frameworks and guidelines security professional encounter.
- **Center for Internet Security (CIS)** - a non-profit that publishes internet security standards;
- **National Institute of Standards and Technology (NIST) 800-53** - a non-regulatory government agency special publication describing security and privacy controls to achieve compliance with the Federal Information Security Management Act (FISMA).  Any organization doing business with a government agency must demonstrate compliance with FISMA;
- **Federal Risk and Authorization Management Program (FedRAMP)** - federal program prescribing the security standards of cloud based information systems;
- **Payment Card Industry Data Security Standards (PCI/DSS)** - created by Visa and Mastercard that establishes security requirements for credit card merchant.  Companies that violate this will have the credit card companies revoke there ability to accept credit cards;
- **Federal Financial Institutions Examination Council (FFIEC)** - maintained by a consortium of financial regulators and outlines security controls expected of financial institutions; and
- **Cloud Security Alliance (CSA)** - another non-profit which has standardized cloud security.

As guidelines are not legally binding, violations do not cause legal or regulatory enforcement actions even if the guideline was written by a regulator.  The process of publishing a law or regulation is time consuming and often fails; therefore, regulators use the guideline process to instruct regulated entities how to act.  Never tell a regulator this, but they are kind of optional!
### Audit
Customers often don't trust an organization's security measures when handling or storing their sensitive data.  These customers will demand the organization to prove reasonable security controls are implemented and effective.  This process is called *vendor management due diligence* and is a critical component of business to business transactions.  As an organization grows its customer base it may find it increasingly more difficult to prove security compliance at scale.  Therefore an organization may seek to obtain a third party certification that is an attestation to the existence and functioning of security controls.  Having such a certification streamlines the operational burden of fielding potential customer inquiries and would otherwise require the organization to be audited directly by every one of their concerned existing and potential customers.  **Service Organization Control Type 2 (SOC2)** and the **International Organization for Standardization (ISO) 27001** are the two most common certifications organizations obtain.

The SOC2 is conducted by an accredited certified public accountant (CPA) and is widely used in the United States.  There also exists a SOC1 which is used to demonstration financial controls (not security) and a SOC3 which is a summarized version of the SOC2.  The SOC2 is a written report usually 50-100 pages that describes the organization's structure, customer security responsibilities, and the security controls being assessed.  The controls themselves are chosen by the organization and verified by the auditor.  The auditor then renders an opinion on the effectiveness of the controls.  The SOC2 is further subdivided by two types and referred to as *type 1* or *type 2*.  A type 1 report is a moment in time evaluation of the existence of a control while a type 2 is an assessment of that control over a 6 months to 1 year time period.  

![[../images/01/SOC2.png|SOC 2 Badge|150]]

Non-US and international companies usually achieve an ISO 27001 certification as it is recognized globally.  An organization will hire an accredited body to conduct the audit of the *information security management system (ISMS)*.  The auditor follows a strict listing of controls and tests them for effectiveness.  The auditor provides a report to the management of the company and a certificate to share with external parties proving compliance.

![[../images/01/iso_27001.png|ISO 27001 Badge|150]]

In both types of audits referenced here the review are reconducted every 6 months to 1 year depending on the engagement.  Auditors perform tests by selecting a random sampling of a population related to a control and verifying system records that prove compliance to a control.  For example, a common security control is to revoke a terminated employee's system access within 24 hours.  An auditor will request a list of all the terminated employees over a time period and then request records of there termination date and access removal.  System reports and screenshots are the preferred type of evidence collected.

## Business Continuity Planning and Disaster Recovery
Information systems maintaining their availability is a component of the CIA triad covered earlier in the chapter.  This level of assurance requires careful planning, design, and testing of systems.  No system is impervious from unplanned downtime so measures must be taken that address what to do if there is an outage.  Such efforts are referred to as **Business Continuity Planning (BCP)** and **Disaster Recovery (DR)** where managers conduct **risk assessments** and **business impact assessments** to determine how a system could fail.  Estimates of how long systems can be tolerated to be down are made during these assessments.  Then disaster recovery plans can the be drawn up on the effort to get systems back online.  
### Risk Assessment
There are a few generalized threats to the availability of information systems.  They include *natural*, *technical*, and *people*.  Natural threats often take form of the natural disasters such as earthquakes, floods, and tornadoes to name a few.  Location needs to be considered when determining the applicability of these threats as some places have more natural threats than others.  For example, there is a higher chance of an earthquake in the California Bay Area while there is no chance of a tornado.  Another threat to the availability of systems technical such as when the content delivery network (CDN) provider Cloudflare suffered a material internet outage for customers due to a border gateway protocol (BGP) misconfiguration[^1].  Cybersecurity incidents can also cause technical outages.  For example, a ransomware attack could cause information systems to go offline.  The last availability risk to consider during a risk assessment is from people.  This risk can arise from purposeful or accidental actions made by individuals.  One time I was decommissioning a network rack and clipped all the ethernet wires in the patch panel but one of them provided internet to an office suite which caused a disruption in business.

The BCP/DR risk assessment is often prepared by operations and technical managers jointly.  It is a written document, such as a spreadsheet, that is updated frequently or at least annually.  Its objective is to define the availability risks faced to information systems and business operations by identifying what could go wrong.  The risk assessment usually consists of a list of risks that fall under the risk categories natural, technical, and people.  The next step in the BCP/DR process is to identify the impacts risks may have to the business.
### Business Impact Assessment
With a risk assessment completed, the business needs to identify the level of impact and inter-dependencies business units have.  The **business impact assessment (BIA)** is a written document, typically another spreadsheet, that lists each business unit and information systems it depends on.  The risk analyst will interview department leads to determine how they would be affected should an information system be unavailable.  The analyst collects this information and rates each department and information system with a priority.  For example in the restaurant industry if the credit card network or equipment becomes unavailable the business would be adversely affected because they couldn't process payments.  Although less than ideal, they restaurant could still conduct business using cash or by collecting card information and running charges latter.  The restaurant would be adversely affected but not out of commission so an appropriate BIA rating for the front of house operation and the credit card network may only be a *medium*. 

During the BIA process the analyst would attempt to measure various thresholds of tolerance and expectations which could also inform the level of priority needed.  This is helpful in the event of an outage of several systems and having a firm understanding which systems to prioritize first - especially if one system depends on another system.  Back to the restaurant credit card system example, the system depends on the availability of electricity to the building.  The back of house depends on electricity to run the lights needed for the cooks to see what they are doing.  Without electricity the restaurant would have to close therefor a disaster recovery team should focus on restoring the electricity before attempting to restore the credit card system.

### Measures
There are common time measurements needed to establish an informed BIA.  These metrics are written in hours, days, or months for each business unit and information system.  The **Recovery Point Objective (RPO)** instructs how much data needs to be restored.  Imagine a database that holds customer sales leads information.  Losing this data would be harmful to the business but it might only cause the loss of potential future sales.  Perhaps an appropriate RPO in this case is a daily backup meaning the business could tolerate the loss of one day's worth of data.  Compare this to a bank's database that stores high volume of customer transactions.  A loss of even one minute of this data could cost the bank millions of dollars.  A real-time backup, or database replication, may be required and an RPO of 1 second is all the bank could tolerate.

A business must also determine how long a system could be down for before the business is severely impacted, or will go out of business permanently.  **Maximum Tolerable Downtime (MTD)** attempts to quantify this threshold.  For example, an accounts payable accounting system used for paying vendors and employees may be determined to have an MTD of one month.  After which vendors will begin terminating contracts and employees will quit due to not receiving payment which would be catastrophic to the business.  

Armed with the knowledge of the RPO and MTD, the analyst can work with business and system administrators on how long it will take to get a system back up and running with a metric called **Recovery Time Objective (RTO)**.  Ideally the RTO is less than the MTD otherwise the business will need to identify alternative methods to close the gap least risk the longevity of the business should an outage occur.  A complete BIA with RPO, MTD, and RTO might look something like the following example:

![[../images/01/bia.png|Business Impact Analysis]]

### BCP/DR Plan
After the risk assessment and BIA process the business can develop a plan on how to address the risk of an outage of a given business unit or information system.  The BCP/DR plan is a written document that describes the roles and responsibilities of all parties.  It will describe who is responsible for communication with the employees of an organization and how to handle customer inquiries.  It will include instructions on how to handle anticipated events such as offsite meeting locations and alternative procedures.  The document usually includes an out-of-band call tree should phone systems become unavailable.  Key personal are typically required to print a physical copy of the BCP/DR plan at their homes in case of an office fire or computer outage making digital copies unavailable.  Some BCP/DR plans go as far as forbidding the chief executive officer (CEO) and the chief financial officer (CFO) from sharing a flight due to the risk of a plane crash and needs of succession planning!  The plan would also establish how the plan is communicated and taught to participating members of the organization so that everyone knows what to do in the event of an outage.  The plan will prescribe how events should be documented and may include template reports to ensure all relevant information is consistently and comprehensively collected.

Once created, the plan should be regularly tested using *table top exercises* where key members work together in a conference room under the pretense of an outage and describe how they would handle a given scenario.  Another form of testing is to perform components of an event and assess the performance of the plan, such as a practice fire drill.  A well planned test will have defined objectives whose performance will be measured against to determine the successfulness of the response actions.  Being well prepared goes a long way when events come to fruition and these efforts could be the difference of if a company survives or not.

## Data Classification
Not all information is worth protecting while some information may require more protective controls than others.  The process of identifying, labeling, and assigning required controls to information is known as **data classification**.  Information, and the systems that process and store them, are assigned a label that indicates who can access the them and what degree of protection is required.  This labeling, or classification, varies between organization and the public sector.  The following graphic illustrates two overly simplified data classification schemes.

![[../images/01/data_classification.png|Data Classification Schemes]]
Usually there are at least three levels of classification with the most open level available for anyone's permitted use.  An example of this *public* or *unclassified* information could be the splash page of a website available on the internet.  Any information on such a site is accessible by everyone.  The next tier is information that is important and should not be made public but may otherwise be available to an audience the a need to know.  Sometimes referred to as *internal* or *secret*, this information requires security controls that ensure access is only made to authorized persons.  The most sensitive data classification is the *confidential* or *top secret* tier.  This data is highly restricted and must have the highest levels of security controls.  A system's *hardware security module (HSM)*, where encrypted secrets are stored, could be an example of an information system and data that reaches this level of classification.

## Identity Access Management
System administrators of information systems are required by security professional to maintain control over the access to networks and systems.  This is accomplished through **identity and access management (IAM)** which has developed into a defined subfield of information security over the last several years.  It isn't uncommon to see companies hiring explicitly for security professionals with IAM experience and some larger organization may hire individuals to only manage IAM.  But the responsibility for ensuring IAM controls falls on both system administrators (or admins) and security professionals.  In a general sense, admins grant and revoke access to systems while security professionals ensure access is securely maintained through access reviews.

A system that ensures IAM practices will establish **authentication, authorization, and accounting (AAA)** capabilities.  The authentication process validates the identity of the entity requesting access to a system where as authorization verifies an authenticated entity is permitted to perform actions on that system.  When accounts of a system interact with the system a record or log of the event should take place which is known as accounting.  The accounting arm of AAA should log authentication and authorization events at a minimum.  Additional log entries in robust systems will include the actions made by each account especially over sensitive features of the system like creating and modifying accounts.

> [!tip] Tip - IAM Lingo
> The shorthand for authentication is *authn* and for authorization is *authz*.

### Identity and Factors
The authentication phase of IAM's AAA requires an **identity** element and a **factor** to validate the identity of an entity.  Identity elements, also referred to as *entities* or *service principals*, are usually not treated as secrets and can often be found publicly.  Examples of an identity include usernames or a physical badge worn on a lanyard around the neck.  A factor is *something you know*, *something you have*, or *something you are*.  The most common example of the factors a password (know), hardware token (have), and biometric scan (are).  The process of presenting identity and a factor and a system making the determination if these elements validate the entity is authentication.

Passwords are wrought with deficiencies which can make the less secure as anyone that knows the password could masquerade as that entity.  Passwords can be leaked or guessed in various ways that we will explore later in this book.  Because of their weakness many secure systems require *multi-factor authentication* that includes at least two different factor types (know, have, are).  For example, during the authentication process an entity must provide their username (identity), password (factor 1 - know) AND a hardware token value (factor 2 - have).

> [!warning] Warning - Common MFA Mistake
> A common mistake when determining the use of MFA is confusing the use of two of the same factors as MFA.  For instance, presenting a password and a pin is not MFA because both factors are something you know.  True MFA systems require the use of different factor types!

### Permissions
After an entity is authenticated they will perform actions against a subject system.  The process of authorization determines if the authenticated entity is allowed to perform these actions which are referred to as **permissions**.  There are many actions that can be conducted by the entity but most conform to *reading*, *writing*, and *executing* and abbreviated as (RWX).  We will explore some common methods on how systems determine permissions in the next section.

There are two principles that should be followed when assigning or assessing entity permissions.  The **need to know principle** evaluates if the entity has a reasonable and confirmed use case for the system or its data.  An individual should not have access to a system if the don't have a need to know its information regardless of that individual's standing in the organization.  This often arises when granting access to an executive at a company.  Just because an executive is responsible to the organization does not mean they should have root access on a server.  If they are granted access when they don't need it, undue exposure to system breach is manifested should that executive's account every be compromised.  After determining if an entity should have access to the system, the administrator must determine how much access the entity should have.  Maintaining just enough access for what is needed for the entity is known as the **least privileged principle**.  Continuing with our executive example, perhaps that executive needs access to the server to access a specific report.  Providing root access to that server provides too many permissions which will violate the least privileged principle.  Perhaps the executive only needs *read* access to specific files on the server in which case granting that access only achieve the least privileged goal.

### Access Control
There are a number of architectures to map entities with sets of permissions to control access in an information systems.  Engineers that design systems must consider the logic of how systems determine access control.  A common architecture to administer who can access what in a system is the **access control list (ACL)**.  The ACL list each entity and the permission they have on an object in that system.  The image below is a screenshot taken from Microsoft Azure demonstrating an ACL for the "/myDirectory" object.  The object lists each entities', or service principal, permissions on that object.

![[../images/01/acl.png|Azure ACL|500]]
This Azure ACL object is administered by the object's owner who can decide and configure which service principals have what level of access to the object.  This type of ACL where the owner of the object decides is known as a **discretionary access control list (DACL)**.  There are other variants of access control to consider, such as **mandatory access control (MAC)** in which another system maintains what users can access data and systems under different data classifications.  Each entity is assigned a *clearance level* and information systems are labeled a *data classification*.  When an entity requests data from the system their clearance level and the classification label is checked against a control list to allow or block the request.

![[../images/01/mac.png|Mandatory Access Control]]

An information system with thousands of service principals and millions of objects would become unmanageable.  Easing the burden of administering access promotes a more secure environment as they can streamline access decisions making a system less complicated.  One strategy to organize access is through **role based access control (RBAC)** in which administrators of an information system can creates a role sharing the same group of permissions.  Once the role is created and permissions configured, the administrator can assign users to the role where they will inherit its permissions.  You could imagine this makes reviews of permissions much easier.

### Managing IAM
Organizations must establish processes to ensure effective access management on their information systems.  The system administrator and security professional have important roles in and IAM system's management.  System administrators are responsible for *provisioning*,  *altering*, *reviewing* and *revoking* access to systems.  Human resource departments typically supply administrators with events, such as employee onboarding or termination, and information, such as user details like name and job type.  The administrator will be alerted on this event and use the information provided to configure access to systems.  The administrator is responsible for ensuring the principles of least privileged and need to know are applied and they must challenge any requests for access that don't seem appropriate or lack detail to make an informed decision.

It is not uncommon for a service principal's use case on a system to change overtime.  This usually results in a user have more access than what is needed and is often referred to as *access drift*.  Identifying and correcting these issues requires frequent reviews and use case validations.  It can be sometimes contentious when removing permissions of a long standing user as they have grown accustom to the higher level of access.  This resistance sometimes deters change and it is important for a security professional to insist on the change when appropriate.  Another common issue is when the deprovisioning process fails to notify a system administrator to remove access.  If an employee is terminated someone must notify the admin to remove that terminated employee's access otherwise it will persist past employment.  Failing to revoke access timely exposes the organization to unauthorized access by a potentially disgruntled former employee.  In 2021, a New York Credit Union lost high volumes of financial data several days after terminating an employee.  The disgruntled ex-employee discovered they still had access to sensitive information systems and as an act of revenge deleted important data [^2].
## Lab Environment Setup
Each chapter of this book will include lab exercises on the topics covered.  Readers are encouraged to complete the labs to gain practical experience and to demonstrate a deeper understanding of the material covered.  Many individuals in the security community contribute to the body of security knowledge through blog posts, how-to videos, and capture the flag challenges.  Becoming proficient in security requires the ability to setup scenarios in a lab environment and experiment with systems.  The labs in this book will use the infrastructure established in the following exercise.

> [!exercise] Exercise - Install VirtualBox
> In this lab, you will install VirtualBox on your host machine to support  three virtual machines (VMs) as test environments that support future lab coursework.
>#### Download and Install VirtualBox
>1. Ensure your processor supports virtualization that is enabled in the BIOS/UEFI.  In Windows, this can be done using the Task Manager.  You must enable virtualization.  You will not be able to proceed with the course if your CPU does not support virtualization!
>
>![[../images/01/lab_01_task_manager.png|Task Manager|500]]
>2. Navigate to [https://www.oracle.com/virtualization/technologies/vm/downloads/virtualbox-downloads.html](https://www.oracle.com/virtualization/technologies/vm/downloads/virtualbox-downloads.html) 
>3. Select Installer (Windows, Mac OS X, Linux):
> ![[../images/01/lab_02_vbox_download.png|VirtualBox Download page|400]]
> 4. Run the installer, follow the prompts, default settings should be fine.  Launch VirtualBox:
> ![[../images/01/lab_03_vbox_installed.png|VirtualBox Startup Window|300]]


> [!exercise] Exercise - Install Kali Virtual Machine
> After VirtualBox is installed on your host machine, you will install a Kali Linux VM.  Kali is a Debian distribution maintained by Offensive Security.  It comes preinstalled with many security tools, lists, and apt repositories that we will be using throughout the course.  You will download the ISO image from the Kali website and manually install the operating system as a VM.  Once installation is complete, you will install the VirtualBox guest additions and configure the VM to share resources with your host computer.
> 
> #### Download and Setup Kali VM
> 1. Navigate to [https://www.kali.org/get-kali/#kali-installer-images](https://www.kali.org/get-kali/#kali-installer-images)
> 2. Select the download button for the 64-bit Installer image:
> ![[../images/01/lab_04_kali_dowload.png|Kali Linux Download Page|400]]
> 3. With the ISO for Kali fully downloaded (~10-20 minutes depending on internet speeds), navigate to the running VirtualBox application and select the “New” button:
> 
> ![[../images/01/lab_03_vbox_installed.png|VirtualBox Startup Windows|300]]
> 4. The VirtualBox "Create Virtual Machine" wizard should appear.  Within the wizard, name the VM “kali” and select the Kali ISO location downloaded in the previous steps.  Then press the Next button.
> 5. Within the "Hardware" wizard page, supply the VM with 4GBs memory and 2 processors (note, these settings can be increased or decreased later if needed) then press Next.
> 6. On the "Virtual Hard disk" page, create select "Create a Virtual Hard Disk Now", change the "Disk Size" to 30GB and press the Next button.
> 7. Within the "Summary" wizard page, review the settings and press Finish.
> 8. With the “kali” VM selected, press the “Start” button to launch the VM in a new window:
> ![[../images/01/lab_05_kali_started.png|Kali Started|400]]
> 9. Select “Graphical Install” within the VM window and hit enter to launch the operating system installation wizard.
> 10. With the VM's installation wizard starts with the "Select a language page.  Select the language "English" and press Continue.
> 11. While on the "Select your location" page, choose your location.  For example, "United States" and then press Continue.
> 12. On the "Configure the keyboard page, select keyboard layout American English and press Continue.
> 13. Allow the Kali installer to run and the wizard will eventually launch the "Configure the network" page.  Enter the hostname “kali” and press Continue.
> 14. On the second "Configure the network page", leave "Domain name" field empty and Continue.
> 15. Next, on the "Set up users and passwords" page, enter your name in the "Full name for the new user" field and press Continue.
> 16. From the second "Set up users and passwords" page, enter any username in the "Username for your account" field and press Continue.
> 17. In the third "Set up users and passwords" page, enter a password in the "Choose a password for the new user" and the "Re-enter password to verify" fields.  Make sure you remember this password!  Press the Continue button to advance the installation.
> 18. In the next wizard page "Configure the clock", select your timezone and press Continue.
> 19. On the "Partition disks" page, allow a moment for the disks to be detected, then select the “Guided - use entire disk” option and press Continue.
> 20. From the second "Partition disks" page, select default partition and press Continue.
> 21. Within the thrid "Partition disks" page, select the “All files in one partition” option and press Continue.
> 22. In the forth "Partition disks" page, select the “Finish partitioning and write changes to disk” to commit the partition changes and then press Continue.
> 23. On the fifth and last "Partition disks" page, select “Yes” to the "Write the changes to disks" question (note default option is no) and press Continue.
> 24. While in the "Software selection" window, wait for the system to install.  Then use the default software selections and press continue.
> 25. Once the software installs after waiting for ~25 minutes, the "Install the GRUB boot loader" window appears.  Select Yes and then press Continue.
> 26. Still on the "Install the GRUB boot loader" page, select the available device (not "Enter device manually") and press Continue to install the boot loader.
> 27. Wait some time for the installation to finish and the "Finish the installation" page will appear.  Press Continue to complete the installation.
> 28. The system will reboot and launch the login menu.  Enter the username and password used during installation.  If the VM boots to a black screen, you may need to increase the "Video Memory" of the VM.  Navigate to VirtualBox, select your VM, press Settings, choose Display from the navigation menu on the left, and then increase the Video Memory.
> ![[../images/01/lab_06_kali_login.png|Kali Login Screen|500]]
> 29. The system will log in and present the Kali desktop.  Right click in the desktop and select “Open Terminal Here” from the context dropdown menu.
> 30. With the terminal open, run the apt update command and then enter your password to update the system.
> `sudo apt update -y`
> 31. After updates have installed, install the VirtualBox guest software using the following command. 
> `sudo apt install -y --reinstall virtualbox-guest-x11` 
> ![[../images/01/lab_07_kali_update.png|Kali Terminal Update and Install]]
> 32. After the guest software is installed, select the Devices menu, Drag and Drop, and then the Bidirectional option.
> ![[../images/01/lab_08_kali_drag_drop.png|VM Drag and Drop Setting]]
> 33. Similarly, select the Devices menu, Shared Clipboard, and select the  Bidirectional setting to enable copying clipboard values between the host and VM.
> 34. Return to the Kali terminal and reboot the VM using the following command.
> `reboot`
> Congratulations, you’ve successfully setup Kali in VirtualBox!  If you have adequate disk space (2x the recommended minimum) then you may consider taking a snapshot of the fresh install in case you ever want/need to start from a clean install.



>[!exercise] Exercise - Install Ubuntu Virtual Machine
> 
> We will use an Ubuntu VM throughout the course as a victim, server, or to illustrate secure configurations.  Ubuntu is another Debian distribution maintained by Conical and is one of the most popular operating systems.  You will download an ISO image and install the system using the unattended installation feature.  Once completed, we will configure the VM to share resources with the host.
> #### Download and Setup Ubuntu VM
> 1. Navigate to [https://ubuntu.com/download/desktop](https://ubuntu.com/download/desktop and download the Ubuntu 22+ LTS image.
> ![[../images/01/lab_09_ubuntu_download.png|Ubuntu Download Page]]
> 2. With the ISO for Ubuntu fully downloaded (~10-20 minutes depending on internet speeds), navigate to the running VirtualBox application and select the “New” button.
> 3. The VirtualBox "Create Virtual Machine" wizard will launch.  On the "Virtual machine Name and Operating System" page, enter "ubuntu" in the name field and select the Ubuntu ISO image you downloaded in the previous step.  Leave the "Skip Unattended Installation" checkbox UNCHECKED and press Next.
> 4. Within the "Unattended Guest OS Install Setup" page, change the username and password, change the domain name to "lan".  Ensure the "Guest Additions" option is checked and press Next.
> 5. In the "Hardware" page, select a "Base Memory" of 4096MB and set "Processors" to 2 CPUs (these settings can be adjusted later if more/less resources are needed).
> 6. On the "Virtual Hard disk" page, choose the option "Disk Size" and set it to 30 GBs then press Next.
> 7. Review your settings on the "Summary" page and press "Finish" to complete the setup.
> 8. Observe the ubuntu VM has been configured and is running in the VirtualBox application.  Select the ubuntu entry and then the Show button to watch the installation progress.  The installation should take 20-30 minutes.
> ![[../images/01/lab_10_ubuntu_install.png|Ubuntu OS Auto Installation]]
> 9. Once installation is complete the VM will reboot to the login screen.  Login with the user account you setup in step 4.
> 10. Similar to Kali, setup the shared clipboard and drag and drop VM settings.  Select Devices, Shared Clipboard, and choose Bidirectional.  Then select Devices, Drag and Drop, and choose Bidirectional.
> Congratulations, you have successfully installed the Ubuntu VM on VirtualBox! If you have adequate disk space (2x the recommended minimum) then you may consider taking a snapshot of the fresh install in case you ever want/need to start from a clean install.



> [!exercise] Exercise - Install Windows Virtual Machine
> The last VM we will be using in our lab environment is a Windows 10 machine.  Similar to Ubuntu, it will act as a victim, server, or be used to demonstrate secure configurations.  You will install an evaluation version so there is no need to purchase a license.  To obtain the ISO, you will download the Windows installation media tool to your host machine, configure the desired ISO, and download it.  You will then create a VM using this ISO and use the unattended installation feature.  After installation we will setup the ability to share resources between the host and the VM.
> #### Download and Setup Windows VM
> 1. Navigate to https://www.microsoft.com/en-us/software-download/windows10 and press the "Download Now" button under the "Create Windows 10 installation media" section.
> ![[../images/01/lab_11_win_download.png|Download Media Creation Tool|500]]
> 2. Open the Downloads folder and run the Media Creation Tool executable which will launch the "Windows 10 Setup" wizard in a new window.
> 3. Within the "Windows 10 Setup" window, accept the licensing and choose “Create installation media (USB flash drive, DVD, or ISO file) for another PC” option.
> 4. On the "Choose which media to use" page of the wizard, use the recommended options and select ISO file.
> ![[../images/01/lab_12_win_iso.png|Media Creation Tool ISO Selection|400]]
> 5. Select the location to save the ISO and the download will begin.  Select Finish once complete (no need to burn to DVD) and the download process should begin.  The download may take 10 to 20 minutes depending on your internet connection.
> 6. After the ISO for Windows download completes, navigate to the running VirtualBox application and select the “New” button which launches the VirtualBox "Create Virtual Machine" wizard in a new window.
> 7. On the "Virtual machine Name and Operating System" wizard page, enter "windows" in the "Name" field then navigate and select the ISO file downloaded from the Media Creation Tool in the "ISO Image" field.  Press the Next button to continue the configuration.
> 8. From the "Unattended Guest OS Install Setup" page, adjust the unattended install setup with username and password of your choosing, set the "Doman Name" to lan, and check the "Guest Additions" options.  We won’t be licensing Windows so don’t worry about the Product Key and press the Next button.
> 9. Within the "Hardware" page, set the "Base Memory" to 4096 MB and set 2 processors.  Press the Next button to continue the configuration.
> 10. On the "Virtual Hard disk" page, select "Create a Virtual Hard Disk Now", enter 40 GB and press Next.
> 11. Review the settings on the "Summary" page and press Finish if all looks correct to start the unattended operating system installation.
> ![[../images/01/lab_13_win_summary.png|Windows VM Summary|500]]
> 12. Windows should take 20-30 minutes to install and can be monitored by selecting Show in VirtualBox on the running windows VM.
> ![[../images/01/lab_14_win_install.png|Windows VM Installation]]
> 13. After the installation completes you will be automatically logged into the VM to the Windows desktop.  You may have to adjust the VirtualBox View settings and/or the Windows display settings for the best experience.  If your window does not show the file menu, try using VirtualBox shortcut keys to display (in Windows right CTRL + Home button).
> 14. Similar to Kali and Ubuntu VMs, setup the shared clipboard and drag and drop VM settings. Select Devices, Shared Clipboard, and choose Bidirectional. Then select Devices, Drag and Drop, and choose Bidirectional.
> Congratulations, you’ve successfully installed Windows in VirtualBox!  If you have adequate disk space (2x the recommended minimum) then you may consider taking a snapshot of the fresh install in case you ever want/need to start from a clean install.


[^1]: BGP Router Leak Causes Cloudflare and Amazon AWS Problems; By Lawrence Abrams; 2019; https://www.bleepingcomputer.com/news/technology/bgp-route-leak-causes-cloudflare-and-amazon-aws-problems/
[^2]: Fired NY credit union employee nukes 21GB of data in revenge; By Sergiu Gatlan; 2021; https://www.bleepingcomputer.com/news/security/fired-ny-credit-union-employee-nukes-21gb-of-data-in-revenge/