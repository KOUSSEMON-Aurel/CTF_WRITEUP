# Bytemancy 2 - PicoCTF 2026

**Points:** 200  
**Author:** LT 'syreal' Jones  
**Challenge Type:** Binary/Networking

## Description

Can you conjure the right bytes? The program's source code can be downloaded here.

Connect to the program with netcat:
```
nc lonely-island.picoctf.net 56229
```

## Challenge Analysis

Looking at the source code in `app.py`:

```python
import sys

while(True):
  try:
    print('⊹──────[ BYTEMANCY-2 ]──────⊹')
    print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
    print()
    print('Send me the HEX BYTE 0xFF 3 times, side-by-side, no space.')
    print()
    print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
    print('⊹─────────────⟡─────────────⊹')
    print('==> ', end='', flush=True)
    user_input = sys.stdin.buffer.readline().rstrip(b"\n")
    if user_input == b"\xff\xff\xff":
      print(open("./flag.txt", "r").read())
      break
    else:
      print("That wasn't it. I got: " + str(user_input))
      print()
      print()
      print()
  except Exception as e:
    print(e)
    break
```

The challenge is straightforward:
1. The program reads raw **binary bytes** using `sys.stdin.buffer.readline()`
2. It expects exactly `b"\xff\xff\xff"` (three 0xFF bytes)
3. If correct, it prints the flag from `flag.txt`

## Key Insight

The program specifically uses `sys.stdin.buffer` which means it reads raw binary data, not ASCII text. This makes it impossible to send using standard tools like `nc` with text input. You cannot type 0xFF bytes directly—**you must send raw binary bytes over the network**.

This is why the hint suggests using **pwntools**: it's designed specifically for sending arbitrary binary data over network sockets.

## Solution

Using pwntools to send raw bytes:

```python
#!/usr/bin/env python3
from pwn import *

# Connect to the remote server
conn = remote('lonely-island.picoctf.net', 56229, timeout=5)

# Wait for the prompt
conn.recvuntil(b'==> ', timeout=5)

# Send 0xFF three times (raw binary bytes) + newline to signal EOF
payload = b'\xff\xff\xff\n'
conn.send(payload)

# Receive and print the flag
import time
time.sleep(0.5)
response = conn.recv(4096, timeout=2)
print(response.decode(errors='ignore'))

conn.close()
```

## Flag

```
picoCTF{3ff5_4_d4yz_5ce8506f}
```

## Key Takeaways

1. **Binary vs Text Input:** When a program uses `sys.stdin.buffer`, it expects raw binary data, not text
2. **Pwntools for Binary Protocols:** Pwntools is the right tool for sending arbitrary binary data over network protocols
3. **Newline Handling:** The `readline()` function expects a newline character to signal end of input, so include `\n` at the end of the payload
4. **Raw Bytes:** Make sure to send the literal bytes `\xff\xff\xff`, not the ASCII string "ff ff ff"

## Tools Used

- **pwntools**: Python library for CTF exploitation and binary communication
- **netcat**: Initial connection (though pwntools handles this internally)
