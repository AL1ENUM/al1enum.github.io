

## Port Scan

```sh
┌──(alienum㉿kali)-[~]
└─$ sudo nmap -A -O -sS 10.10.72.52 
[sudo] password for alienum: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-27 16:16 EEST
Nmap scan report for 10.10.72.52 (10.10.72.52)
Host is up (0.086s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 87:c4:26:88:4f:42:ae:2c:74:8b:ff:66:2d:f0:68:9d (RSA)
|   256 05:f5:06:fc:dc:86:f8:f2:ba:e2:ee:df:14:c3:3d:e4 (ECDSA)
|_  256 92:74:cb:39:e1:ce:31:90:13:9d:4c:ee:27:f8:06:bc (ED25519)
8080/tcp open  http    Werkzeug httpd 1.0.1 (Python 2.7.17)
|_http-server-header: Werkzeug/1.0.1 Python/2.7.17
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=4/27%OT=22%CT=1%CU=40799%PV=Y%DS=2%DC=T%G=Y%TM=60880EC
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=FB%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)SEQ(
OS:SP=FB%GCD=1%ISR=10A%TI=Z%CI=Z%TS=A)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=
OS:M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11)WIN(W1=F4B3%W2=F4
OS:B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW7
OS:%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%
OS:RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIP
OS:CK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   79.54 ms 10.8.0.1 (10.8.0.1)
2   77.74 ms 10.10.72.52 (10.10.72.52)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.33 seconds
                                                                                
┌──(alienum㉿kali)-[~]
└─$ 
```

## Directory Scan

```sh
TGUE?O·S·K·MTUEGI·SYENFE·TOI···SRO·T·SF·OYT···O·T·KUMH·I·AE·NMK··
```