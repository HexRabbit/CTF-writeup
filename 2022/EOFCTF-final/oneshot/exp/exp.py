#!/usr/bin/env python3
from pwn import *
import hashlib
context.log_level = 0

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

r = remote('chals1.eof.ais3.org', 45127)

r.recvuntil(b'sha256(')
chal = r.recvn(16).decode()

p = log.progress(f'Solving POW "{chal}"')
ans = pow_solver(chal, 22)
r.sendlineafter(b'POW answer: ', ans.encode())
p.success('Solved!')

exp = open('./exploit', 'rb').read()
r.sendlineafter(b'Exp size: ', str(len(exp)).encode())
r.sendafter(b'Send your exp:', exp)

r.interactive()
