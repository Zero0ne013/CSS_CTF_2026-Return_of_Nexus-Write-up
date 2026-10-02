## Assignment

Category: PWN

Difficulty: Beginner

The dockside ticket office manages temporary harbour access tickets.

You can create, cancel, edit, and use a ticket.

A cancelled ticket should no longer be usable, but this old terminal may not handle ticket memory safely.

Can you turn a cancelled ticket into emergency harbour access?

Flag Format: CSSCTF{}

## Reconnaissance

Starting with basic enumeration, running the file command on dockside_ticket reveals that it is an x86-64 binary. To analyze it further, I opened it in Ghidra.

<img width="650" height="58" alt="Pasted image 20261001215249" src="https://github.com/user-attachments/assets/43696387-2134-4809-9b8c-2a6019ea9908" />

The challenge description hints at an issue with ticket cancellation. Let's look at the logic. 

From the main function, we can see that the program takes user input (options 1-5) to perform different actions.

<img width="634" height="873" alt="Pasted image 20261001215610" src="https://github.com/user-attachments/assets/d44e5297-e029-4418-8fd4-93340f2ba80c" />

Since the description mentioned cancellation, I checked the cancel_ticket function.

<img width="423" height="286" alt="Pasted image 20261001215703" src="https://github.com/user-attachments/assets/c69fdd2f-7549-440d-8830-d9cba9e4d006" />

We can see that it free()s the ticket memory but does not set the pointer to NULL. Lets see if we can somehow use it.

Next, let's examine how we can get "emergency harbour access". I looked for relevant functions and found open_gate.

<img width="494" height="211" alt="Pasted image 20261001215906" src="https://github.com/user-attachments/assets/16cabc84-f6eb-4e1c-90aa-d04de1fdab2a" />

Oh, that was fast, we can see the flag, and by entering it we can see that it is valid ://.

But for the sake of the PWN challenge, let's see how we can exploit the application to actually execute this function and pop the flag in our terminal :] .

We know that the cancel function just free the memory, lets look how the ticket is created.

<img width="482" height="390" alt="Pasted image 20261001220250" src="https://github.com/user-attachments/assets/b517becf-1828-4e2c-9e42-ef7bb8c44a61" />

Here we can see that the ticket allocation reserves 0x28 bytes. It saves the magic value 0x53455547 and sets a function pointer to deny_access at offset 0x20.

Let's look at edit_ticket.
Here, I realized that the edit_ticket function completely overwrites the original ticket data without protecting the function pointer!

<img width="387" height="302" alt="Pasted image 20261001220856" src="https://github.com/user-attachments/assets/5fb1fa50-f39d-440b-a2d9-bf13204a55bf" />

Finally, looking at use_ticket, we can see that it simply executes whatever function pointer is located at offset 0x20 of the ticket structure, with no checks to verify if the ticket has been freed or modified.

<img width="410" height="260" alt="Pasted image 20261001221048" src="https://github.com/user-attachments/assets/fed86a27-a38a-47c0-af79-552615eb4036" />

## Exploitation

Because the edit_ticket function is vulnerable and lets us overwrite the entire structure, we do not even need to free the ticket as the assignment suggests! All we have to do is create a ticket, edit it to overwrite the function pointer with our desired address, and then use it.

First, I grabbed the address of the open_gate function, which is 0x40125f.

<img width="684" height="29" alt="Pasted image 20261001221746" src="https://github.com/user-attachments/assets/e6861820-f745-4034-8d5f-e4efbf674407" />

Then, I wrote the following exploit script:

```python
from pwn import *

p = process("./dockside_ticket")

p.sendlineafter(b"> ", b"1")  # create

p.sendlineafter(b"> ", b"3")  # edit

payload = b"A" * 0x20 + p64(0x40125f)
p.send(payload)

p.sendlineafter(b"> ", b"4")  # use

p.interactive()

```

Output:

<img width="556" height="190" alt="Pasted image 20261001221906" src="https://github.com/user-attachments/assets/6af6bc53-d052-4061-b6e1-e9a93506d32c" />

It worked! By hijacking the function pointer, the program executed open_gate and printed the flag.
