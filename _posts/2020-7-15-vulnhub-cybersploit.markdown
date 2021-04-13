---
layout: post
title:  "VulnHub - CyberSploit 1"
date:   2020-7-15 20:10:34 +0300
categories: [vulnhub,walkthrough]
pin: true
tags: [CTF,enumeration,guessing,decoding,exploitdb]
---
You’ll find this vm here :  `https://www.vulnhub.com/entry/cybersploit-1,506/`
#### Port Scan

![image](/assets/img/cybersploit/1.png)

#### Enumeration

![image](/assets/img/cybersploit/2.png)

Found `username` : `itsskv`

![image](/assets/img/cybersploit/3.png)

####  Directory scan, found robots.txt

![image](/assets/img/cybersploit/4.png)

![image](/assets/img/cybersploit/41.png)

#### SSH login

credentials : `itsskv`:`cybersploit{youtube.com/c/cybersploit}`

![image](/assets/img/cybersploit/42.png)

#### Found the second flag | binary to text

![image](/assets/img/cybersploit/5.png)

#### Privesc to Root

- command : `uname -a`

![image](/assets/img/cybersploit/6.png)

#### Searchsploit

![image](/assets/img/cybersploit/61.png)

- Send the script to the target machine

![image](/assets/img/cybersploit/7.png)

## Rooted

![image](/assets/img/cybersploit/8.png)
