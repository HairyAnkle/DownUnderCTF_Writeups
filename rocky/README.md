# Rocky — Reverse Engineering Challenge

## Challenge Description
An underdog boxer gets a once-in-a-lifetime shot at the world heavyweight title and proves his worth through sheer determination.

## Recon
Basic checks with `checksec` and `file`:

---

```c
┌──(kali㉿kali)-[~/Desktop]
└─$ checksec --file=./rocky
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH   Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   80 Symbols     No    0    
```

```c
┌──(kali㉿kali)-[~/Desktop]
└─$ file rocky 
rocky: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=12a85b1a1e6c5bb107276f005ddac83c26136f0b, for GNU/Linux 3.2.0, not stripped
```

Decompilation of `main()` showed:
- The program prompts for input.
- Computes `MD5(input)` into a 16-byte buffer.
- Compares against a hardcoded 16-byte value split across two 64-bit constants:

```c
  local_18 = 0xd2f969f60c4d9270;
  local_10 = 0x1f35021256bdca3c;
```

If hashes match, it calls `reverse_string()` and `decrypt_bytestring()` to reveal the flag.

---

## Extracting the Target MD5

The constants are compared as raw bytes, so converting to a contiguous MD5 target:

```c
0x70 0x92 0x4d 0x0c 0xf6 0x69 0xf9 0xd2 0x3c 0xca 0xbd 0x56 0x12 0x02 0x35 0x1f
```

Hex string:

```c
70924d0cf669f9d23ccabd561202351f
```

---

## Cracking the Hash

Using `hashcat` with the rockyou wordlist:

```c
echo '70924d0cf669f9d23ccabd561202351f' > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

Result:
```c
70924d0cf669f9d23ccabd561202351f:emergencycall911
```

So the correct input is:

```c
emergencycall911
```

---

## Getting the Flag

Running the binary with the cracked input:

```c
┌──(kali㉿kali)-[~/Desktop]
└─$ echo "emergencycall911" | ./rocky
Enter input: Hash matched!
DUCTF{In_the_land_of_cubicles_lined_in_gray_Where_the_clock_ticks_loud_by_the_light_of_day}
```

The Flag is:

```c
DUCTF{In_the_land_of_cubicles_lined_in_gray_Where_the_clock_ticks_loud_by_the_light_of_day}
```

