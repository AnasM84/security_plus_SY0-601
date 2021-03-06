# Social Engineering Techniques

## 001. Introduction to Social Engineering
- impersonating someone else to trick somebody (to click link, make a phone call, share information).
  * *couple of examples*:
    * identity fraud
    * false payment invoice

## 002. Phishing and Related Attacks
Emails with intent to compromise person or computer, by clicking a link, or opening an attachment in such mail.  
**NOT** really a *spam*, spam is advertising.

- **Spear phishing** a targeted phishing.
- **Whaling** a targeted phishing for important person (big fish).
- **Watering hole attack** observing/guessing which sites organization is using and infecting one of them with malware.
- **Vishing** phishing done using phone (voice).
- **Smishing** phishing done using SMS.
- **Pharming** credential harvesting by tricking user, where user inputs his credentials (for example: bank) into a faked site that looks legit, but it's not.

ways of reducing phishing attacks:
- user training
- email security

## 003. Low Tech attacks
- **dumpster diving** - can be prevented by *information disposal process* regarding hard drives, thumb drives, papers,
so any information that is no longer needed can be properly managed and destroyed.
- **tailgating** or **piggybacking** - trick to gain physical (unauthorized) access - can be prevented by "one person, one card at the time" policy
- **typo squatting** - incorrect website - site with a typo in it that tricks user into a faked site that looks legit, but it's not.

## 004. Why Social Engineering Works

- **authority** - or *presumed* target more willing to comply in presence of authority
- **intimidation** - 
- **consensus** - "everyone does it"
- **scarcity** - "limited lifetime offer"
- **trust** - or familiarity
- **urgency** - no time to think (this is implied in other reasons)

## 005. The Top Social Engieering Tool
Strategies in phishing
- hook
- attachment in email
- mix of legit and fake links in link
This may lead to:
- credential harvesting
- malware on user's system

Protection from phishing:
- don't open attachments in emails
- don't click any links in emails

TIP: check out blogs:
- Akmai
- F5 labs

## 006. Identifying a Phishing Mail
- **urgency**
- **grammar and spellinng**
- **gut feeling** - not 100% correct, but useful
- **attachment** - not expected, or not mentioned
- **subject line** - mismatched, or weird
- **timestamp** - weird time
- **links** - incorrect URL by 1 or 2 characters, no TLS (HTTPS) link

## 007. Social Engineering Toolkit
Credential harvesting demo in Kali Linux.

## 008. Review Quiz
Video quiz.



# Cyber Attack Techniques

## 009. Introduction to Cyber Attack Techniques
Just an intro.

## 010. Malware
Malicious software.

The software that nobody wants.
- **trojans** - software that installs malware in the background
- **worm** - virus that works without user intervention
- **fileless virus** - virus that lives in memory (RAM)
- **PUP** - potentially unwanted program
- **bot** - agent that runs on computer and can be activated remotely
- **cryptoalware** - malware that encrypts data on your computer and hacker wants ransom for unencryption - also **ransomware**
- **spyware**
- **keylogger** - tracks down your keystrokes
- **RAT** - Remote Access Trojan
- **Rootkit** - low-level malware that's hard to detect

End User Training helps preventing all those threats.

## 011. Password Attacks
- **brute force** - trying all the permutations with repetition
- **dictionary attack** - trying all the passwords in the dictionary/database
- **spray attack** - trying few common passwords against large number of users
- **offline attack** - for example: comparing *hashed* versions of password against stolen *hashed* password database, slow, but hacker can take as much time as he wants
- **rainbow table** - precomputed *hash* values of tables

Limiting login attemtps helps preventing all those threats.

## 012. Password Attack Example
Kali Linux attack example.

Methods used to compromise a user's password.
- steal the *hash* and attack it offline
- trick the user into using a clear text protocol

## 013. Cyber Physical Components
- **malicious USB cable** - with a specificaly designed chip/circuit
- **malicious flash drive**
- **card cloning**
   * skimming - reading or cloning a card

Most secure way to access a facility is card and PIN (multi factor)

## 014. Adversial AI
Security of AI and machine learning. Making sure that it gets the right/safe data.

## 015. Supply Chain Security
- Products with chips that have vulnerabilities.
- 3rd party management software with malware

## 016. Cryptographic Attacks.
- **hash collision** different data sets create same *hash* value (rare thing)
- **downgrade** - for example: changing TLS from 1.3 to 1.2

When storing passwords **salt** is the mechanisim to make it harder for an attacker to discover password.

## 017. Review Quiz
Video quiz.

Remote access to computer
- **RAT**
- **bot**
- **backdoor**

`netstat` show open ports on lInux and can indentify RAT activity.

Most accurate indicator of **rootkit** is: *has* on core system files have changed.



# Application Attacks

## 018. Introduction to Application Attacks
Just an intro.

## 019. Injection Attacks
SQL, DLL, LDAP, XML (and more) injection attacks.

Using specially crafted input (exploiting syntax)
that may lead to:
- data corruption/ system damage
- privlage escalation

*Proper input validation* is a way to protect form SQL or LDAP injection attacks.

## 020. Cross Site Scripting
**XSS** - acronym for Cross Site Scripting
Type of attack that can run malicious JavaScript in the user's browser.


## 021. Poorly Written Apps
- **Memory leak** - app doesn't release allocated memory which "clogs" part of RAM
- **Buffer overflow**
- **Error handling** 
- **Integer overflow** - when numeric value is too big it wraps aroud
- **Race condition**
  * **time of check**
  * **time of use**
- **Misconfiguration**
  * **filesystem traversal**

Proper error handling can prevent most of these.

A *buffer overflow* is an attack that tries to input more memory that the application can accomodate.

## 022. Overflow Attack Demo
Overflow attack demo in Kali Linux.

## 023. Poorly Written App Attack
Web forms hacking demo (using developer tools) in Kali Linux.

## 024. Impersonation
- **session replay**
- **pass the hash**
- **Cross Site Request Forgery** - CSRF - attack that tricks computer to use existing credentials (authentication) to make request to a 3rd party website.

## 025. Error Handling Attack
Lack of authentication attack demo in Kali Linux.

## 026. Additional Application Attacks
- **Downgrade**
- **SSL stripping**
- **API** Application Programming Interface - if unsecure, it can be exploited
- **driver manipulation**
  * **shimming** - not modyfing the code, but arguments in API call
  * **refactoring** - modified code
- **pointer/object dereference**

## 027. Password Recovery Fail
Demo in Kali Linux.

Solution: Configure limited attempts.

## 028. Review Quiz
Video quiz.



# Network Attacks

## 029. Introduction to Network Attacks
It's not when our network will be attcked, but **how** our network will be attcked.

## 030. Wireless Attacks
- **Initialization Vector** (IV) - (What are the main differences between a nonce, a key and an IV?)[https://crypto.stackexchange.com/questions/3965/what-is-the-main-difference-between-a-key-an-iv-and-a-nonce]
- **Evil twin**
  * **rogue access point**  - duplicated access point used for an attack...
  * **disassociation frame** - send this frame which disconnects user from orginal access point...
  * **jamming** - then jams the original router, so it cannot reconnect to it.

- **Shadow IT** - user brings his own device (not authorized)
- **RADIUS**

- **blue snarfing** - pulling bluetooth data from a bluetooth device
- **blue jacking** - pushing bluetooth data to a bluetooth device

- **RFID** - Radio Frequency Identification
- **NFC** - Near-field Communication

## 031. In-line / On-path Attacks
Or **Man-in-the-middle** attack.
Note: proxy server is man-in-the-middle, but it's authorized, and actually used to increase security.

- **Unauthorized DHCP Server** - for example: brodcasts malicious gateway, so that data goes through attecker server, but then goes out through intended, autorized gateway

- **Layer 2 ARP Spoofing**
- **Unauthorized L3 router**
- **DNS poisioning**
- **typosquatting**

- **man-in-the-browser**

Primary reason an ARP attack is successful on a wired network is lack of security controls on the layer 2 switch.

## 032. Layer 2 attacks
- **ARP** Address Resolution Protocol, correlation between IP Address (layer 3) and MAC Address (layer 2). Not protected.
- **ARP poisoning** lying about ture MAC Address
- **MAC flodding** Media Access Control (MAC) flodding - filling up source MAC Addres table on a switch with many bogus source MAC Addresses 
- **MAC cloning**
- **802.1Q Ethernet trunking** - using dynamic trunk negotiation for getting access to different VLANs
- **DoS Attack** - Denal of Service Attack
- **STP** Spanning Tree Protocol - eliminate L2 loops

What is ARP poisoning?
- Incorrect L3 to L2 mapping

## 033. Domain name system (DNS)
- Name resolution

- **Domain hijacking**
- **DNS poisoning**
- **URL redirection** Universal Resource Location redirection
- **DNS Tunneling** - exploitiong UDP (L4, which DNS uses) for tunnelling trafick that's not DNS, but looks like DNS 

Incorrect reply information is being returned to clients from their name server. What is this causing?
- DNS poisoning

## 034. Distributed denial-of-sevice (DDoS)

- **Operational Technology (OT)**
- **Abnormal traffic patterns**
  * **Indicator of Compromise (IoC)**

When a DDoS is being done, what type of computers make up this group of zombies?
- Botnets

## 035. Malicious code or script execution

- **PowerShell**
  * **Command Line Interface (CLI)**
- **Python**
- **Bash shell**
- **Visual Basic for Applications (VBA)**
- **Macros**

Malware can be implemented via Macros in word processing and spreadsheet documents. True or false?
- True 

## 036. Remediation Options

- **Next-Gen Firewall (NGFW)**
- **Local Host Based Protection**
- **Limited End User Permissions**
- **Disable Unneeded Services/Ports**
- **2FA or MFA Authentication** - Two-Factor or Multi-Factor Authentication
- **Defense in Depth**

A syn-flooding attack is trying to ipact the availability of our server. The attack is launched simultaneously from multiple systems. 
What type of attack is this? 
DDoS
- 
## 037. Review Quiz
Video Quiz

Which attack is going to have the greates impact regarding availability of the system being attacked?
- DDoS

An Attacker is spoofing the layer 2 address of the gateway, tricking the switch to forward frames to the attacker instead of the router.
What can prevent this?
- ARP Inspection

Which Bluetooth related attack extracts or pulls data from a targeted device?
- Bluesnarfing

What is the term for incorrect name server record information being provided to clients?
- DNS Poisoning



# Threat Actors and Inteligence Sources

## 038. Introduction to Actors, Vectors, and Intelligence Sources

## 039. Threat Actors
- **Insider/internal threat**
- **External/outsider threat**
- **Advanced Persistent Threat (APT)**
- **Script kiddies**
- **Hacktivists**
- **State actors**
- **Competitors**
- **Criminal syndicates**

What is shadow IT?
- IT implemented without authorization

## 040. Attack Vectors
Way of an unauthorized access that can compromise the system.
- **Direct access**
- **Wireless**
- **Email** - user training helps preventing this
- **Supply chain**
- **Social media**
- **Removable Media**
- **Cloud**

## 041. Threat Inteligence Sources
- **Tactics, Techniques, & Procedures (TTP)**
- **Open-source inteligence (OSINT)**
- **Info Sharing & Analysis Org (ISAOs)**
  * [IT-ISAC](it-isac.org)
  * [ATT&CK](attack.mitre.org)
  * [Exploit database](exploit-db.com)
  * [National Vulnerability Database](nvd.nist.gov)
  * [Virus Total](virustotal.com)
  * [Common Vulnerabilities and Exposures](cve.mitre.com)
  * [AUTOMATED INDICATOR SHARING](https://www.cisa.gov/ais)
    - **STIX** Structured Threat Information Exposition
    - **TAXII** Trusted Automated Exchange of Indicator Information
      * system used to share files - [TAXII Intro](https://oasis-open.github.io/cti-documentation/taxii/intro.html)
  * [TALOS](talosinteligence.com)
- **Threat maps**
- **File/code repositorires**
- **Dark web**

## 042. Threat Maps
- [FireEye](https://www.fireeye.com/)
- [Kaspersky Cybermap](https://cybermap.kaspersky.com/)
- [Fortinet Threatguard](http://threatmap.fortiguard.com/)
- [Spamhaus Threatmap](https://www.spamhaus.com/threat-map/)
- [Bitdefender Threatmap](https://threatmap.bitdefender.com/)
- [Digital Attack Map](https://www.digitalattackmap.com/#anim=1&color=0&country=ALL&list=0&time=18763&view=map)
- [Akamai Real Time Attack Visualizations](https://www.akamai.com/uk/en/resources/visualizing-akamai/)
- [TALOS](https://talosinteligence.com)
- [Checkpoint Threatmap](https://threatmap.checkpoint.com/)
- [a10networks Threatmap](https://threats.a10networks.com/)

There is a value in using a diversity of products and services, as it may improve security awareness and readiness. True or false?
- True

## 043. Additional Sources for Research
- **Vendor website**
- **Vurneability feeds**
- **Conferences**
- **Academic journals**
- **RFC** Request For Comments - details on protocols
- **Local industry groups**
- **Social media**
- **TTP** Tactics, Techniques & Procedures

You need to research a specific IPv4 protocol, as it was used in a new attack.
Which document type should you use?
- RFC

## 044. Review / Quiz
Which is an example of shadow IT in the context of attack vectors?
- unauthorized impementation of tools or services, including cloud

What tools might a script kiddie use to compromise a public facing IoT device?
- vulnerability database
- off the shelf hacking tool
- google hacking
- social media

Which of the folowing could be motivations for hacking/attacking a system?
- Ruin a company's reptation
- Extract company secrets
- A deeply felt cause
- Financial gain
- Curiosity



# Vulnerabilities and Security Risks

## 045. Introduction to Vulnerabilities and Security Risks

## 046. Cloud vs. On-prem Vulnerabilities
Questions to ask:

What/Which?
- Encryption
- Access Control
- Authentication
- API
- Fault tolerance
is used?

Which security question should be asked that is unique to cloud services, compared to on-prem or a local data centeer?
- Where is the data geographically stored?

## 047. Zero-day Attacks
Nobody knew about the vulnerability, before the attack was performed. 

Which of the following is the primary reason a Zero-Day vulnerability exists?
- Vulnerability is unknown

## 048. Weak configurations
- **Default settings**
- **Unsecure root accounts**
- **Errors** - misconfigurations - we should estabilsh baselines to mittigate that
- **Unsecure protocols** - without encryption - for example: http, ftp, tftp
- **open ports and services** 
  * Linux(?): `netstat -tulpn`
  * Windows: [How to Find Listening Ports with Netstat and PowerShell](https://adamtheautomator.com/netstat-port/)
- **supply chain**

Which of the following conttribute to ar are symptoms of weak configurations?
- Weak or insecure protocols
- Older embedded systems
- Firmware that is not updated
- Unused open ports

## 049. Telnet with IPsec Demonstration
Sometime we have to use unsecure protocol. For example: configuration file.
Then, we must use VPN (for example IPsec VPN) to secure the connection.

Which protocols are insecure by default (choose three)?
- FTP
- Telnet
- TFTP

## 050. Third-Party Risks
- **Vendor management**
- **Outsourced code development**
- **Data storage**
- **Patch management**

Which of the following can do the most to best protect against vulnerabilities in the supply chain?
- Vendor management

## 051. Patch Management
Does software need updates? Absolutely YES!

- **Firmware, OS, apps**
- **Legacy platforms**
- **Data exfiltration**
- **Identity, Financial, Reputation, Availability** losses

Which items could lead to a lack of appropriate patches being applied?
- Lack of inventory in our systems
- Older embedded OS in IoT devices
- Non-supported firmware in IoT devices

## 052. Vulnerabilities Review Quiz
One of the users was tricked into clicking on an email in a phishing attack.
Email, Web, Network IPS, Network NGFW, as well as local Anti-Virus did not prevent a ransomware infection.
What is this a result of? (Choose 3)
- Email was encrypted
- Zero-day attack
- Insufficient user training

Which file transfer protocols transmit data in plain text, and should be avoided for sensitive data? (choose 2)
- FTP   (TCP 21)
- TFTP  (UDP 69)

You are considering repuroposing an older IoT device into a new part of your network.
What risk realted items should you consider? (choose 3)
- Is the device supported by the vendor?
- Is the firmware up to date?
- Is the embedded OS vulnerable?

Which type of compromise would be most likely from an external threat labeled as "script kiddie"?
- Internet-facing unpatched system

you have implemented network based IPS and NGFW filtering, including DLP.
What would allow data exfiltration despite these technical controls? (choose all that apply)
- Mobile hotspot
- Shadow IT router/AP
- Encrypted email
- Disgruntled employee



# Techniques Used in Security Assessments

## 053. Introduction to Security Assessments
"Measure twice, cut once"

## 054. Vulnerability Scan Overview
Vulnerability scanners:
- [tenable nessus](https://www.tenable.com/products/nessus)
- [rapid7 nexpose](https://www.rapid7.com/products/nexpose/)

- **credentialed vs. non-credentialed scan.**

Which type of vulnerability scan uses valid system credentials as a part of the intrusive scan?
- Credentialed scan

## 055. Network Scan Demonstration
- `nmap`
  * `zenmap`

Which open/listening port implies that DNS services are running?
- 53

## 056. Positive and Negative Scan Results
Try to reduce false positives when running a scan. **Credentialed scan** might help with that.
- **False negative** there was a vurneability but didn't reported it

A vulnerability scan does NOT report a LINUX vulnerability againts a Windows server. What is this result?
- True negative

## 057. CVE and CVSS
- **CVE** Common Vulenrabilities and Exposures - IDs
  * [Common Vulnerabilities and Exposures](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures)
- **CVSS** Common Vulnerability Scoring System
  * 0-10 scale (0 least risk, 10 most risk)
  * calculation based on:
    - Attack Vector
    - Attack Complexity
    - Required Permissions/Rights
    - User Interaction
    - Impact to C.I.A (Confidentiality, Integrity, Avaliability)
  * [CVSS Calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)

## 058. Security Information & Event Management (SIEM)
Centralised system for managing events/logs. They allow us to react to incidents in organised manner.
- **deduplication** summary (corellation) of hundreds of ralated events
- **User behaviour analysis**
Data can be written to **WORM** (Write Once, Ready Many) drive.

## 059. Threat Hunting
- **Bug bounty**
- **Inteligence fusion**

What is the goal of threat hunting?
- Find vulnerablilities before hackers do

## 060. Security orchestration, automation and response (SOAR)
Key components of SOAR are:
1. **Vulnerability and Threat Management**
2. **Response to Incidents**
3. **Automation of Seurity Operations**

[Gartner SOAR reviews](https://www.gartner.com/reviews/market/security-orchestration-automation-and-response-solutions)

## 061. Security Assessment Review Quiz
A vulnerability scan indentifies CVE-2019-5021 an Alpine Docker Image Vulnerability.
The system indentified with this is a Windows Workstation with no hpervisor enabled.
What does this scan result represent?
- False Positive

What can be done to reduce false positives in vulnerability scans?
- Credentialed scans
- Target specific systems based on OS
- Only use specific plug-in in Scanner

Which type of activity would be looking for unpathced systems, without causing harm or compromising the system? (choose 2)
- Vulnerability scanning
- Reconnaissance

What are 3 categories that can benefit from vulnerability scans?
- Applications
- Networks
- Web Applications

Company policy restricts workstations from running plain text web and remote access services.
Which ports should the vulnerability scanner look for?
- TCP port 23
- TCP port 80



# Penetration Testing Techniques

## 062. Introduction to Penetration Testing
While vulnerability scan checks for threats, penetration testing checks whether exploit can compromise the system.

## 063. Pen Testing Overview
- **Privilage escalation**  taking advantage of one system to make a pivot and **lateral movement** to other systems
- **Persistance** keeping access after you get in
- **Cleanup** cover any traces of your activity
Before pentesting is done:
- **Rules of engagement** what is allowed, what is not allowed (setting up the rules)
Gathering information:
- **Passive reconnaissance** victim doesn't even know
  * **footprinting** collecting as much info as you can
  * **web crawlning** company's website
  * **sniffing** eavesdropping the traffic (network packets)
  * **drones**
  * **war driving**
- **Active reconnaisance**
 * **port scanning** or **ping scanning**
 Performing attack:
 - using general ideas/techniques mentioned before: **privilage escalation**, **persitance**, **cleanup**
 - simple example: **directory traversal**
- **intrusive** vs **non-intrusive**
Final step:
- **Reporting** what was found, what attack were used

 Even if you don't manage the network, pentesting IS allowed if you have a valid user account on the system. True or false?
 - False

 ## 064. OSSTMM
 Open Source Security Testing Methodology Manual

 What is the first step for pen testing?
 - Permission

 ## 065. Resources from NIST
 National Institute of Standards and Technology.

Special Publication 800-115:
 [Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/publications/detail/sp/800-115/final)

 ## 066. Penetration Testing Execution Standard
 PTES - [Penetration Testing Execution Standard](http://www.pentest-standard.org/index.php/Main_Page)

 One of the first items in "pre-engagement" phase is identifying scope.

## 067. Pen Testing Demo
Explicit permission first!

In Kali Linux:
- `yersinia` or `yersinia -G`
 * CDP flooding
 * Sending DHCP discovery packets
 * DTP (Dynamic Trunking Protocol) attack: enable trunking
 * STP (Spanning Tree Protocol) attack

## 068. OWASP
Open Web Application Security Project
[OWASP Top Ten](https://owasp.org/www-project-top-ten/)
[Hacksplaining OWASP Top Ten](https://www.hacksplaining.com/owasp)

## 069. Security Team Exercises
- **Red Team** Offense
- **Blue Team** Defense
- **White Team** Neutral (Referees)
- **Purple Team** Read and Blue Team combined.

## 070. Pen Testing Review Quiz
Which of the following are considered passive reconnaissance?
- Network sniffing
- Crawling a website
- DNS lookup

Which of the following could be used to discover WiFi networks?
- War chalking
- War driving
- War flying
- Social Engineering

Which of the following should be done in penetration testing?
- Only within the rules of engagement & scope

What is the biggest difference between vulnerability scanning and pen testing?
- Pen testing test to see if an exploit works



# Security Concepts for the Enterprise

## 071. Introduction to Security Concepts for the Enterprise

## 072. Configuration management
- **baseline configuration**
Current and available documentation:
- **diagrams** - logical and physical
- **Internet protocol (IP) schema** IPAM - IP Address management
  * [Infoblox IPAM](https://www.infoblox.com/products/ipam-for-microsoft/)
- **Standard naming convention**
  * IT naming conventions best practices

  [Microsoft Security Compliance Toolkit 1.0](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10)

A user has requeste a change that deviates from the security configuration baseline. How should this be handled?
- Change Management

## 073. Data protection.
Where data is?
- **in transit/motion**
- **at rest**
- **in processing**
Protection mechanisms:
- **Encryption**
- **DLP** Data Loss Prevention
- **User training**
- **Masking** - scrambling - for reports, for pen testing replicas
- **Tokenization** - using placeholder (non-sensitive equivalents) values instead of real ones

Objective | Method
----------|-------
Data integrity  | Hashing
Availability    | Fault Tolerance
Authentication  | 2FA
Confidetiality  | Encryption
Accounting      | Logging

## 074. Hashing
Validating whether there were changes over time in file.
Checking for data integrity.

- `certutil -hashfile <filename>` or `Get-FileHash -Path <filename>` on Windows
  * more info `certutil -hashfile -?` or `help Get-FileHash`

SHA-1 is more robust than MD5
SHA-256 is ireversible
Hashing can verify data integirty.

## 075. Deception and Disruption
- **honeypot** sanitized decoy to see who is attacking - [What is honeypot?](https://docs.rapid7.com/insightidr/honeypot/)
- **honeyfile**
- **honeynet**
- **fake telemetry**
- **DNS sinkhole** DNS knows reputation of sites, and if it's a malicious one, it redirects user to warning "stop" site

Which system (including open ports) is used to attract attackers, but if the system is compromised, no sensitive data is disclosed?
- honeypot

## 076. SSL/TLS Inspection
Firewall is man-in-the-middle that does **SSL/TLS inspection** (applicatiion layer inspection) - decrypts and analyzes data.
For privacy reasons we want to tell firewall NOT TO decrypt finnancial or medical data -.

What is the purpose of SSL/TLS inspection?
- Allow our proxy/NGFW to perform application layer inspection

## 077. Site Resiliency
- **Hot site** up and running, ready (most expensive)
- **Cold site** no network or systems, getting ready, up and running from SCRATCH (least expensive)
- **Warm site** some of the infrastructure

Considerations:
- **Geographical**
- **Data soveregnity**
- **API**

Which alternate site has some network infrastructure and a few systems, but is not fully functional and ready to go site?
- Warm Site

## 078. API Considerations
**API** Application Program Interace

An application programming interface (API) could allow an attacker to compromise confidentiality, data integrity, and/or availablity. True or false?
- True

## 079. Quiz and Review
Which of the following are hashing algorithms?
- MD5
- SHA-1
- SHA-256
* **NOTE**: AES and RC4 are encrtyption algorithms!

Which of the following can hashing verify?
- Integrity of a packet
- Intergity of a program
- Integrity of update or hotfix

Which of the following are reversible?
- AES
- 3DES
* **NOTE**: encryption methods (using keys) are reversible, hashing is NOT reversible

Which type of systems may include intentional vulnerabilities?
- Honeypot



# Cloud Computing and Virtualization

## 080. introduction to Cloud Computing and Virtualization

## 081. Virtualization Overview
- **Hypervisor** 
  * bare metal hypervisor (type 1 hypervisor) - run directly on hardware
  * hosted hypervisor (type 2 hypervisor) - run inside operating system
- **Virtual Machines** VMs - easy to run, but also easy to forget **VM sprawl**
- **VM escape** - breaking out of VM and interacting with host operating system
- **Cloud services** for VMs
  * **resource services**

## 082. Cloud Models
- **IaaS** Infrastructure as a Service - customer manages OS
- **PaaS** Platform as a Service - for example for app development
- **SaaS** Software as a Service - cloud applications, for example Office 365
- **XaaS** Anything as a Service
- **FaaS** Function as a Service - serverless architecture

Location/ownership:
- **On-prem**
- **Off-prem**
- **Public**
- **Private**
- **Hybrid**
- **Communuty**

## 083. MSPs and MSSPs
- **MSP** Managed Service Provider
- **MSSP** Managed Security Service Provider

## 084. Desktop Virtualization
- **Edge Computing**
- **Fog Computing**

- **VDI** Virtual Desktop Infrastructure
- **VDE** Virtual Desktop Environment

- **Thin Client** used to access VDI

## 085. Deploy a VM
ESXi Demo.

## 086. Modyfiing a VM
ESXi Demo.

## 087. Containers and Microservices

## 088. Infrastructure as Code and SDN
- **SDN** Software Defined Networking - for example: vSphere for Configuring (networking) multiple ESXi hosts
- **SDV** Software Defined Visibility

## 089. Quiz and Review
The customer is responsible for OS patches and virtualized networking
Which cloud model is being used?
- IaaS

If a VM is performing slowly, what is able to provide it more CPU or memory?
- Hypervisors



# App Development, Deployment, and Automation

## 090. Intro to App Development, Deployment, and Automation

## 091. Development Environments
- **Software diversity**
- **Compiler**
- **Development Methodologies**
- **CI/CD** Continuous Integration, (Delivery), and Deployment
- **Testing**
  * White Box
  * Black Box
  * Elasticity & Sclability
  * **QA** Quality Assurance
  * **Staging** - near exact replica to perform tests on
- **Provisioning and deprovisioning**

## 092. Separation of Duties
Change control, change approval, rollback procedure.

Which of the following is an example of when two different people with unique responisibilities work toghther on a project?
- Separation of duties

## 093. Secure Coding Techniques
- **Input Validation** protects from SQL injection
- **Normalization** checking for invalid characters
- **Stored procedures** using premade SQL statements, not custom ones
- **Obfuscation/camouflage**
- **Code reuse/dead code**
- **Memory manegement** to prevent resource exhaustion
- **Error handling**
- **SDKs** Software Development Kits (and Thired-party Libraries)
- **Code Signing**

## 094. OWASP BWA
Open Web Application Security Project Broken Wen Appliication

Demo of OWASP BWA

## 095. Automation and Scripting
Benefits of automation or scripting:
- **Automated courses of action**
- **Continious automation**
- **Continous validation**

Which feature of a software repository assists developers in making sure they are on the correct fork or update of code?
- Version control

## 096. Improving Integrity
- **TPM** Trusted Platform Module

Which is name of the chip that can store keys and assist in confirming the integrity of a system?
- TPM

## 097. Review Quiz



# Authentication and Authorization Design Concepts

## 098. Intro to Authentication and Authorization Concepts

# 099. AAA Overview
- **AAA** Authentication, Authorization and Acounting
  * Authentication - verify the user identity - identify who the user is, and verify it
  * Authorization - What the user is allowed to do
  * Accounting - Tracking what the user did

Which method/protoco; is often used between the network device providing access and the back end authentication server?
- RADIUS

# 100. Authentication Methods
- **OTP** One-Time Password
  * **Token Generator** generated tokes are OTPs
  * **TOTP** Time-based One-Time Password
  * **HOTP** HMAC-based One-Time Password (Hash Message Authentication Code)
  * **SMS** Short Message System - another way to deliver OTP
- **Static codes**
- **Push notifications**
- **Smart Card authentication**
- **SSO** Single Sign On
- **Federation** Domain trust across organizations

When Domain A trusts the authentications performed in Domain B, what is this an example of?
- Federations

# 101. Biometrics
- **Fingerprint**
- Eye scan
  * **Retina**
  * **Iris**
- **Facial**
- **Voice**
- **Gait analysis** the way one moves
- **Vien** in the hand
How effective the biometrics is (how accurate it is) is measured by **efficacy rate**.
- **false acceptance**
- **false rejection**
When these two are equal it's called **crossover error rate**

# 102. Multifactor Authentication (MFA)
3 Factors/Categories:
- **Something user knows** - for example: Password
- **Something user has** - for example: Smart Card
- **Something user is** - biometrics

When it comes to authenticating:
- **2FA** Two-factor Authentication - using two dfferent categories
Additional category:
- **Someone you know** - vouches for you

# 103. Quiz Review
Which centrailzed authentication option uses RADIUS and can perform network-based authentication of the device, at the edge of the network?
- 802.1X

Which options below are in the same factors/caregories?

 Knows   |    Has   |   Is
---------|----------|--------------
pin      | smart card | fingerprint
password | OTP generator |
birthday |            |

What is FAR (False Acceptance Rate)?
- How often bio authentication system incorrectly indentifies a user