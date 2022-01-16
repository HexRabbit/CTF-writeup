#!/usr/bin/env python3
##
# https://github.com/balsn/proof-of-work/blob/master/solver/python3.py
##
import hashlib

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
            return i

