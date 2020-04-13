#!/usr/bin/python3
import os, stat, sys

def get_inp(status):
    print(status, end='')
    sys.stdout.flush()
    data = sys.stdin.buffer.readline().strip()
    return data

def write():
    file = get_inp('Give me file: ')
    offset = int(get_inp('Give me offset: '))
    data = get_inp('What to write: ')
    mode = 'wb'
    with open(file, mode) as f:
        f.seek(offset)
        f.write(data)

def make_exec():
    file = input('Give me file: ')
    os.chmod(file, stat.S_IXUSR)


write()
make_exec()
