## Assignment

Category: PWN
Difficulty: Beginner

The dockside ticket office manages temporary harbour access tickets.

You can create, cancel, edit, and use a ticket.

A cancelled ticket should no longer be usable, but this old terminal may not handle ticket memory safely.

Can you turn a cancelled ticket into emergency harbour access?

Flag Format: CSSCTF{}

## Reconisence

We go dockside_ticket by running file we can see that it is binary file x86-64 arch. To futher analyze this file I opend it in ghidra.

![[Pasted image 20261001215249.png]]

By the description we can guess that there will be some issue with cancellation. So lets look at it.

From main we can see that based on args (1-5) it do different actions.

![[Pasted image 20261001215610.png]]

So lets look at cancel_ticket function since it is in description.

![[Pasted image 20261001215703.png]]

We cab see that it just free the ticket but do net set the pointer to NULL, lets see if we can somehow use it. 
Let continue our examination by look at how we can get emergency harbour access, this will be probably open_gate function.

![[Pasted image 20261001215906.png]]

Oh, that was fast we can see the flag, and by entering it we can see that it is valid ://.

We could end here by lets look how we can use this app to run this function to get this flag in our terminal :] .

We know that the cancel function just free the memory lets look how the ticket is created.

![[Pasted image 20261001220250.png]]

Here we can see that the ticket allocate 0x28B and the it saved 0x53455547 and pointer to function deny_access, By futher investigation I found that edit_ticket completly rewrite the original ticket. 

![[Pasted image 20261001220856.png]]

And in the use ticket we can see that there is no control if the ticket is freed or not.

![[Pasted image 20261001221048.png]]

Also we do not need to free the ticket as assigment suggest, we just can create ticket and then edit it so we will put there our new address lets try it. Lets get the open_gate address.

![[Pasted image 20261001221746.png]]

Now lets run following code:

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
![[Pasted image 20261001221906.png]]

And it happend! We can clearly see the flag!