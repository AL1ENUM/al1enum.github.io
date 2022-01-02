---
layout: post
title:  "PowerShell - Port Scan"
categories: [PowerShell]
tags: [PowerShell,PortScan,Ping]
---

#### Reasons to create your own Port Scan Script

1. You are not allowed to download and install programs on the computer you are working on
2. You build a better view of how systems work
3. You can improve it and update it immediately
4. Many other reasons

#### Target IPs and Ports

```powershell
$ips = ("192.168.1.1", "192.168.1.3", "192.168.1.15");
$ports = (21, 22, 80, 443);
```

#### Check if Target is Alive

Before the port scan i use the cmdlet Test-Connection to send a ping command to remote computer to check whether the remote machine is up or down. This will save very much time.

```powershell
foreach ($ip in $ips) {

    if (Test-Connection -BufferSize 32 -Count 1 -ComputerName $ip -Quiet) {
        Write-Host "[+] The "$ip" is Online"
        Write-Host "[!] Port Scan starting ..."

        ## add here port scan code

    else {
            Write-Host "[-] The "$ip" is Down"
    }
```

#### Port Scan using Socket

```powershell
foreach ($port in $ports) {
           try {
               ## perform socket Connection
               $socket = New-Object System.Net.Sockets.TcpClient($ip, $port);

           }
           catch {

           };
           # if the port is closed the socket will be null
           if ($socket -eq $null) {
               Write-Host $ip":"$port" - Closed";

           }
           else {

              Write-Host $ip":"$port" - Open";
              $socket = $null;
           }
       }
```

#### All Together

```powershell
$ips = ("192.168.1.1", "192.168.1.3", "192.168.1.15");
$ports = (21, 22, 80, 443);

foreach ($ip in $ips) {

    if (Test-Connection -BufferSize 32 -Count 1 -ComputerName $ip -Quiet) {
        Write-Host "[+] The "$ip" is Online"
        Write-Host "[!] Port Scan starting ..."
        foreach ($port in $ports) {
            try {

                $socket = New-Object System.Net.Sockets.TcpClient($ip, $port);

            }
            catch {

            };

            if ($socket -eq $null) {
                Write-Host $ip":"$port" - Closed";

            }
            else {

               Write-Host $ip":"$port" - Open";
               $socket = $null;
            }
        }
    }
    else {
        Write-Host "[-] The "$ip" is Down"
    }



}
```

#### Run the script

![image]( /assets/img/powershell-scan/1.PNG)

