# Zeus Invocation — Reverse Engineering CTF Challenge

## 📜 Challenge Description
We’re given a 64-bit ELF binary that claims to "summon Zeus" if invoked correctly.  
The program checks specific command-line arguments and then prints a hidden message — our flag.

---

## 🔍 Analysis

### 1. Argument Checks
The binary requires:
- **Argument 1**: `-invocation`
- **Argument 2**:  
  ```
  To Zeus Maimaktes, Zeus who comes when the north wind blows, we offer our praise, we make you welcome!
  ```

If these match, execution continues to the decoding routine.

---

### 2. Encoded Data
Inside `main`, a 51-byte block is constructed from constants:

```c
local_58 = 0x0c1f1027392a3409;
local_50 = 0x011512515c6c561d;
local_48 = 0x5a411e1c18043e08;
local_40 = 0x3412090606125952;
local_38 = 0x12535c546e170b15;
local_30 = 0x3a110315320f0e;
uStack_29 = 0x4e4a5a00;
```

These values are stored in **little-endian** order.

---

### 3. XOR Decoding
The program calls:

```c
xor(&local_98, "Maimaktes1337");
```

Where:
```c
for (i = 0; i < 0x33; i++) {  // 51 bytes
    buf[i] ^= key[i % 0xd];   // 13-byte repeating key
}
```

Key = `"Maimaktes1337"`

---

### 4. Python Solution

```python
import struct

# Constants from the ELF
data_parts = [
    0x0c1f1027392a3409,
    0x011512515c6c561d,
    0x5a411e1c18043e08,
    0x3412090606125952,
    0x12535c546e170b15,
    0x3a110315320f0e,
    0x4e4a5a00
]

# Pack into little-endian bytes
encrypted = (
    b''.join(struct.pack('<Q', p) for p in data_parts[:-2]) +
    struct.pack('<Q', data_parts[-2])[:7] +
    struct.pack('<I', data_parts[-1])
)[:51]

# XOR with key
key = b"Maimaktes1337"
decrypted = bytes([encrypted[i] ^ key[i % len(key)] for i in range(len(encrypted))])

print(decrypted.decode())
```

---

### 5. Output
```
DUCTF{king_of_the_olympian_gods_and_god_of_the_sky}
```

---

## 🏁 Flag
```
DUCTF{king_of_the_olympian_gods_and_god_of_the_sky}
```
