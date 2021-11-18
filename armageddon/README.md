# HACKTHEBOX: Armageddon

## Recon and Enumeration

Nmap scan shows a web app running Drupal7
![nmap](screenshots/nmap.png)

The web application on `http://10.10.10.223` is somewhat minimal.
![webapp](screenshots/webapp.png)

## Exploitation and user.txt

Searching exploitdb for Drupal 7 shows a large number of potential exploits. After some trial and error, Drupalgeddon2 worked.
![searchsploit](screenshots/searchsploit.png)
![searchsploitcopy](screenshots/searchsploitcopy.png)

Run the exploit with `ruby exploit.rb http://10.10.10.223/`
![exploit](screenshots/exploit.png)

Viewing the contents of `.gitignore` shows that `settings*.php` may contain sensitive info.
![gitignore](screenshots/gitignore.png)

View the contents of `./sites/default/settings.php` to reveal credentials.
![dbcreds](screenshots/dbcreds.png)

Use the creds `drupaluser:CQHEy@9M*m23gBVj` to read the contents of the drupal database.
![showtables](screenshots/showtables.png)

Show the contents of the `users` table. It reveals a user named `brucetherealadmin` and a password hash.
![userstable](screenshots/userstable.png)

Cracking the password with mode 7900 gets the creds `brucetherealadmin:booboo`
![booboo](screenshots/booboo_hashcat.png)

SSH into the machine using those creds.
![ssh](screenshots/ssh.png)

## Privilege Escalation and root.txt
Running `sudo -l` shows that the user can run `/usr/bin/snap install *` as root without a password.
![sudolist](screenshots/sudolist.png)

The gtfobins entry for snap privilege escalation requires `fpm`, which is not installed on the box.
![snap gtfobins](screenshots/snap_gtfobins.png)

Instead, a search in exploitdb for snap shows a local privilege escalation exploit.
![searchsploit snap](screenshots/snap_searchsploit.png)

Copy the privesc exploit and upload it to the Armageddon box.
![snap searchsploit copy](screenshots/snap_searchsploitcopy.png)
![curl privesc](screenshots/curl_privesc.png)

Modify the DirtySock Exploit
![modify dirtysock](screenshots/modify_dirtysock.png)
![modified dirtysock](screenshots/modified_dirtysock.png)

Base64 decode the payload into a file.
![base64](screenshots/base64.png)

Install the snap like shown in gtfobins.
![snap install](screenshots/snap_install.png)

Change user with creds `dirty_sock:dirty_sock` who can run all commands without a password.
![dirty_sock](screenshots/dirty_sock.png)
![root](screenshots/root.png)
