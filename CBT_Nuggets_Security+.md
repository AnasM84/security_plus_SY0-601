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

## 019. Injection Attacks

## 020. Cross Site Scripting

## 021. Poorly Written Apps

## 022. Overflow Attack Demo

## 023. Poorly Written App Attack

## 024. Impersonation

## 025. Error Handling Attack

## 026. Additional Application Attacks

## 027. Password Recovery Fail

## 028. Review Quiz