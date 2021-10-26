---
layout: post
title:  "VulnHub - Cewlkid"
date:   2021-03-07 10:10:05 +0300
categories: [vulnhub,walkthrough]
pin: true
tags: [CTF,cewl,burpsuite,psaux,enumeration,Base64]
image: /images/cewl.jpg
---
You’ll find this vm in  `https://www.vulnhub.com/entry/cewlkid-1,559/`

- An intermediate boot2root. The name is a hint. The start is CTF but the end is real world and worth the effort

## Port Scan

![image]( /assets/img/cewlkid/1.png)

## Brute force | Burpsuite

![image]( /assets/img/cewlkid/2.png)

```
 cewl -d 2 -m 5 -w words.txt http://10.0.2.14:8080/index.php
```

![image]( /assets/img/cewlkid/3.png)

#### Burpsuite -> send to Intruder

![image]( /assets/img/cewlkid/4.png)

#### Select wordlist

![image]( /assets/img/cewlkid/5.png)

#### Start the Attack

![image]( /assets/img/cewlkid/7.png)

- `admin`:`Letraset` returns different length and status
- Possible the valid Credentials

## Upload reverse shell

![image]( /assets/img/cewlkid/8.png)

## Spawn Shell

![image]( /assets/img/cewlkid/9.png)

## Hidden credentials

![image]( /assets/img/cewlkid/11.png)

## Base64 decode

![image]( /assets/img/cewlkid/12.png)

## What is ps aux

![image]( /assets/img/cewlkid/psaux.png)

## Login as lorem & ps aux

![image]( /assets/img/cewlkid/13.png)

- Found credentials -> `cewlbeans`:`fondateurs`

![image]( /assets/img/cewlkid/14.png)

- su cewlbeans

![image]( /assets/img/cewlkid/15.png)

## Rooted

![image]( /assets/img/cewlkid/16.png)
