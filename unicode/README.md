# HACKTHEBOX: Unicode

*Unicode* is a medium difficulty Linux box.
It first involves exploiting insecure validation of a JWT cookie by changing the "jku" value to point to the *redirect* feature of the web application so the "jku" redirects to the attacker's jwks file. Changing the "user" value to "admin" on the JWT cookie gains admin privileges on the web application.
From the admin dashboard, an attacker can bypass a filter using unicode normalization to exploit a path traversal vulnerability. Disclosing the `/etc/nginx/sites-enabled/default` file hints at a `db.yaml` file, which is located in `/home/code/coder/db.yaml`.
That yaml file contains ssh creds, giving access to the box. The user can run `sudo /usr/bin/treport` as root without a password. `/usr/bin/treport` is an ELF binary, which can be decompiled to it's python source, revealing that the user can download a url from `file://<filename>` to read files as root after changing the upper/lowercase of `file://`.

## Recon and Enumeration
First, run an nmap scan on the box. Port 22 is running OpenSSH and port 80 is running an Nginx web app.
![nmap](screenshots/nmap.png)

On the front page of the web application, there are links to three interesting subdirectories: `/login`, `/register`, and `/redirect`.
![index](screenshots/index.png)

The `/redirect` directory simply accepts a parameter of `?url` and redirects the user to that url. For example, visiting http://10.10.11.126/redirect/?url=github.com/sadeli413 redirects the user to github.com/sadeli413.
![redirect](screenshots/redirect.png)

##### Creating an account and getting a JWT cookie
Click the *Register* button and create an account.
![register](screenshots/register.png)

Then log in with the new account.
![login](screenshots/login.png)

After logging in, the user is greeted with a dashboard. There are links to `/pricing` and `/upload` but those links are not very important.
![dashboard](screenshots/dashboard.png)

Looking at the cookies shows that there is one session cookie titled *auth*, and the value is some sort of string.
```
auth: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYWx0ZXJlZ28ifQ.vLYudmVXs2uv7L2zQrotRngAU-Qv49nmd-IjsyvOeLl7VsWjtTZJjqTbOjdMXxrEW960dbXPIZmDGPVD3oAXfv6Dauy2q35m9zr7k9WBV3Aq6KY-LZoRJh3iZPrPBRrx0IJxzDVuOcR3WHKoQKUqSAJGZ97uWSHO-CxSM0kXsbQ4yDMlCR1dUIZUmNiJ1Xi7xvf_iJzWQdj48nFcF4oIPwiKz2FdF1YqaDjUeVzCZ5Lrfj5ve5rm4TbgDAOttqqWMkEpC2aDVhE2-RMD2klRZAY0KcBuYQS2aHSX7o-lAUVgMMsuQ_gB0VWzlehIHjsyb5vjXyxFMFxTsqywNxN4Ww
```
![cookies](screenshots/cookies.png)

Attempting to base64 decode this string shows that it is a JWT cookie.
![base64](screenshots/base64.png)

Throw this cookie into https://jwt.io and take a look at what makes up the JWT. It is using the 'RS256' algorithm so we need to get an RSASHA256 public and private key in order to sign the token. The JWT is also using a JKU in order to validate the token at http://hackmedia.htb/static/jwks.json
![jwtio](screenshots/jwtio.png)

http://hackmedia.htb is just the original web app, and http://hackmedia.htb/static/jwks.json is the JWKS file. If we can tamper the token to point the JKU towards our own JWKS file, then we can validate our own RSASHA256 keys.
![hackmedia](screenshots/hackmedia.png)
![jwks](screenshots/jwks.png)

## Exploitation and user.txt

##### Tampering the JWT cookie
The website https://mkjwk.org/ can be used to create a public and private key to sign the JWT.
Select the options Algorithm:RS256 and KeyID:SHA256. After generating the keys, copy 1) the public key, 2) the private key, 3) the n value, and 4) the e value. 
![mkwk](screenshots/mkjwk.png)


Next, wget the jwks.json file from hackmedia and overwrite the n and e values.
![wget](screenshots/wget.png)
![tampered jwks](screenshots/tampered_jwks.png)

Now that we have the public and private keys to sign the token, and our own JWKS file to verify the token, we can
1. Change the "jku" value in the token from "http://hackmedia.htb/static/jwks.json" to our own tampered jwks.json file at "10.10.14.143/jwks.json". 
2. Change our username from "alterego" to "admin"

Take the public and private keys, and paste them into the *Verify Signature* section of jwt.io. Change the username to "admin" and change the jku to 
![tampered jwks](screenshots/tampered_jwt.png)

Start a simple HTTP server and change the cookie to our tampered JWT. When the box reaches out to the JKU, it should use our own jwks.json instead of the hackmedia jwks.json. However, validation fails and the server never reaches out to our machine for the jwks.json
![failed](screenshots/failed.png)

It's likely that the server strictly checks for the jku to come from hackmedia.htb. Fortunately, hackmedia.htb has a `/redirect` function. Changing the "jku" to `http://hackmedia.htb/redirect/?url=10.10.14.143/jwks.json` doesn't work, but changing the "jku" to `http://hackmedia.htb/static/../redirect/?url=10.10.14.143/jwks.json` successfully validates the token, thus changing our "user" to admin.
![jku](screenshots/jku.png)

Changing and saving the auth cookie to the tampered JWT sends a redirected GET request to "10.10.14.143/jwks.json" and successfully logs the user in as "admin"
![admin](screenshots/admin.png)

##### Enumerating the admin dashboard
On the admin dashboard are severall links that point to `hackmedia.htb/dashboard/#` or `hackmedia.htb/logout/`. However underneath the *Saved reports* section are links to `hackmedia.htb/display/?page=<file>`
![admin dashboard](screenshots/admin_dashboard.png)

After clicking on one of those links to either *monthly.pdf* or *quarterly.pdf*, they simply return text.
![quarterly](screenshots/quarterly.png)

##### Exploiting path traversal/file disclosure
Since the url specifies in input of a filename, this URL may be vulnerable to local file inclusion or path traversal. Test this with the url `hackmedia.htb/display/?page=../../../../../etc/passwd` but the page redirects to 404 with a message stating
> We do a lot of input filtering you can never bypass our filters. Have a nice day.

![file not found](screenshots/filenotfound.png)

Several methods such as URL encoding, PHP wrappers, and null bytes fail to bypass the filter. After some testing, it turns out that the filter is vulnerable to Unicode Normalization. Using this [unicode equivalency chart](https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html) to use the unicode character "‥" instead of ".\." will bypass the filter.

Visit the url http://hackmedia.htb/display/?page=%E2%80%A5/%E2%80%A5/%E2%80%A5/%E2%80%A5/etc/passwd (using the unicode character "‥") to disclose the /etc/passwd file. There are two users with bash shells: *root* and *code*.
![etc passwd](screenshots/etc_passwd.png)

##### Enumerating the filesystem with path traversal
Since this is an Nginx application, exploit the file disclosure vulnerability to read the sites-enabled onfiguration file, which is usually at `/etc/nginx/sites-enabled/default`. This file typically has interesting info about the web application.
![sites enabled](screenshots/sites_enabled.png)
After reading this file, we can gather a couple bits of information.
1. There is a comment suggesting that there may be a password in the file `db.yaml`
2. The path `/home/code/coder/static/styles/` may exist.

After searching for this `db.yaml` file along the path, we find it at `/home/code/coder/db.yaml`. It leaks the password `B3stC0d3r2021@@!`
![db](screenshots/db.png)

This password can be used to log in via ssh as the user *code*.
![code](screenshots/code.png)

## Privilege escalation and root.txt

##### sudo -l
First run `sudo -l` to list commands the user may run with sudo. The user `code` may run the command `sudo /usr/bin/treport` as root without a password. The file `/usr/bin/treport` is a ELF binary, and when interrupting the program with ^C, it shows that the source is a python script.
![sudo list](screenshots/sudo_list.png)

##### Decompiling elf to python
Download the treport binary so it can be decompiled and analyzed for vulnerabilities.
![treport](screenshots/treport.png)

Extract the ELF binary into a **.pyc** file using [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor), then decompile the **.pyc** file into a **.py** file using [decompyle3](https://github.com/rocky/python-decompile3).
Since decompyle3 requires python 3.8, I have to downgrade from python 3.10 to 3.8. This can be done easily using [pyenv virtualenv](https://virtualenv.pypa.io/en/latest/)

Create a virtual environment for python 3.8
![pyenv](screenshots/pyenv.png)

Next, download and run pyinstxtractor on the treport binary.
![pyinstxtractor](screenshots/pyinstxtractor.png)

Enter the treport_extracted directory and run decompyle3 on the treport.pyc file. The output is the decompiled python source of the treport binary.
![decompyle3](screenshots/decompyle3.png)

Here are the full contents of `treport.py`. The `download` function is particularly interesting. Though it prevents command injection, it simply curls a url and saves the file. Though the string `file` is blacklisted (preventing a user from entering `file://<filename>`), this can be simply bypassed by changing the case to `FILE`.
```python
# decompyle3 version 3.8.0
# Python bytecode 3.8.0 (3413)
# Decompiled from: Python 3.8.0 (default, Dec 12 2021, 00:41:13) 
# [GCC 11.1.0]
# Embedded file name: treport.py
import os, sys
from datetime import datetime
import re

class threat_report:

    def create(self):
        file_name = input('Enter the filename:')
        content = input('Enter the report:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        file_path = '/root/reports/' + file_name
        with open(file_path, 'w') as fd:
            fd.write(content)

    def list_files(self):
        file_list = os.listdir('/root/reports/')
        files_in_dir = ' '.join([str(elem) for elem in file_list])
        print('ALL THE THREAT REPORTS:')
        print(files_in_dir)

    def read_file(self):
        file_name = input('\nEnter the filename:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        contents = ''
        file_name = '/root/reports/' + file_name
        try:
            with open(file_name, 'r') as fd:
                contents = fd.read()
        except:
            print('SOMETHING IS WRONG')
        else:
            print(contents)

    def download(self):
        now = datetime.now()
        current_time = now.strftime('%H_%M_%S')
        command_injection_list = ['$', '`', ';', '&', '|', '||', '>', '<', '?', "'", '@', '#', '$', '%', '^', '(', ')']
        ip = input('Enter the IP/file_name:')
        res = bool(re.search('\\s', ip))
        if res:
            print('INVALID IP')
            sys.exit(0)
        if 'file' in ip or ('gopher' in ip or 'mysql' in ip):
            print('INVALID URL')
            sys.exit(0)
        for vars in command_injection_list:
            if vars in ip:
                print('NOT ALLOWED')
                sys.exit(0)
        else:
            cmd = '/bin/bash -c "curl ' + ip + ' -o /root/reports/threat_report_' + current_time + '"'
            os.system(cmd)


if __name__ == '__main__':
    obj = threat_report()
    print('1.Create Threat Report.')
    print('2.Read Threat Report.')
    print('3.Download A Threat Report.')
    print('4.Quit.')
    check = True
    while True:
        while True:
            if check:
                choice = input('Enter your choice:')
                try:
                    choice = int(choice)
                except:
                    print('Wrong Input')
                    sys.exit(0)
                else:
                    if choice == 1:
                        obj.create()

        if choice == 2:
            obj.list_files()
            obj.read_file()
        else:
            if choice == 3:
                obj.download()
            else:
                if choice == 4:
                    check = False
                else:
                    print('Wrong input.')
# okay decompiling treport.pyc
```

On the ssh session, run `sudo /usr/bin/treport`. Download a report and input the string `FILE:///root/root.txt`. This will download the `/root/root.txt` file, and save it. Then the contents can be read using the treport program normally.
![root](screenshots/root.png)
