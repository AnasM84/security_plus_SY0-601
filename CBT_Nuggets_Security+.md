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
It's not whaen our network will be attcked, but **how** our network will be attcked.

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
Incorrect L3 to L2 mapping

## 033. Domain name system (DNS)
Name resolution

- **Domain hijacking**
- **DNS poisoning**
- **URL redirection** Universal Resource Location redirection
- **DNS Tunneling** - exploitiong UDP (L4, which DNS uses) for tunnelling trafick that's not DNS, but looks like DNS 

Incorrect reply information is being returned to clients from their name server. What is this causing?
DNS poisoning

## 034. Distributed denial-of-sevice (DDoS)

- **Operational Technology (OT)**
- **Abnormal traffic patterns**
  * **Indicator of Compromise (IoC)**

When a DDoS is being done, what type of computers make up this group of zombies?
Botnets

## 035. Malicious code or script execution

- **PowerShell**
  * **Command Line Interface (CLI)**
- **Python**
- **Bash shell**
- **Visual Basic for Applications (VBA)**
- **Macros**

Malware can be implemented via Macros in word processing and spreadsheet documents. True or false?
True 

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

## 037. Review Quiz
Video Quiz

Which attack is going to have the greates impact regarding availability of the system being attacked?
DDoS

An Attacker is spoofing the layer 2 address of the gateway, tricking the switch to forward frames to the attacker instead of the router.
What can prevent this?
ARP Inspection

Which Bluetooth related attack extracts or pulls data from a targeted device?
Bluesnarfing

What is the term for incorrect name server record information being provided to clients?
DNS Poisoning



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
IT implemented without authorization

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
