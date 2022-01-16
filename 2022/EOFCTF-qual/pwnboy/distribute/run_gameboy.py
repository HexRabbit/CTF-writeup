#!/usr/bin/env python3
import sys
import os
import tempfile
import secrets
import hashlib
from pathlib import Path

##
# https://github.com/balsn/proof-of-work/blob/master/nc_powser.py
##
class NcPowser:
    def __init__(self, difficulty=22, prefix_length=16):
        self.difficulty = difficulty
        self.prefix_length = prefix_length

    def get_challenge(self):
        return secrets.token_urlsafe(self.prefix_length)[:self.prefix_length].replace('-', 'b').replace('_', 'a')

    def verify_hash(self, prefix, answer):
        h = hashlib.sha256()
        h.update((prefix + answer).encode())
        bits = ''.join(bin(i)[2:].zfill(8) for i in h.digest())
        return bits.startswith('0' * self.difficulty)

def main():
    powser = NcPowser()
    prefix = powser.get_challenge()
    print(f'''
sha256({prefix} + ???) == {'0'*powser.difficulty}({powser.difficulty})...
''')

    ans = input('POW answer: ')
    if not powser.verify_hash(prefix, ans):
        print('Not correct!')
        return

    print('Passed!')

    rom_size = int(input('Gameboy ROM size: '))

    print('ROM data:', flush=True)
    rom = sys.stdin.buffer.read(rom_size)

    assert len(rom) == rom_size, 'Read failed'

    with tempfile.NamedTemporaryFile(buffering=0, suffix='.gb') as f:
        f.write(rom)
        assert Path(f.name).stat().st_size == rom_size, 'Input bytes not flush into ROM'

        os.system(f'timeout 20 /home/pwnboy/jitboy {f.name} 2>/dev/null')

if __name__ == '__main__':
    main()
