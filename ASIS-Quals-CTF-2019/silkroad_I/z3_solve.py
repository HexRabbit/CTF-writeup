#!/usr/bin/env python2
from z3 import *

def puzzle(a1):
    v7 = int(a1)
    result = 0
    if ( not (v7 % (len(a1) + 2)) and a1[4] == '1' ):
        v6 = v7 // 100000
        v5 = v7 % 10000
        if ( 10 * (v7 % 10000 // 1000) + v7 % 10000 % 100 // 10 - (10 * (v7 // 100000000) + v7 // 100000 % 10) == 1
                and 10 * (v6 // 100 % 10) + v6 // 10 % 10 - 2 * (10 * (v5 % 100 // 10) + v5 % 1000 // 100) == 8 ):
            v4 = 10 * (v5 // 100 % 10) + v5 % 10;
            if ( (10 * (v6 % 10) + v6 // 100 % 10) // v4 == 3 and not ((10 * (v6 % 10) + v6 // 100 % 10) % v4) ):
                v1 = len(a1) + 2
                v2 = (len(a1) + 2) * v1
                if ( v7 % (v5 * v6) == v2 * (len(a1) + 2) + 6 ):
                    result = 1
    return result

S  = [BitVec('u%d'%i,8) for i in range(9)]
v4 = S[6] + S[8]
solver = Solver()
solver.add(S[4] == 1)
solver.add(10*S[5] + S[7] - 10*S[0] - S[3] == 1)
solver.add(10*S[1] + S[2] - 2*(10*S[7] + S[6]) == 8)
solver.add((10*S[3]+S[1]) / v4 == 3)
solver.add((10*S[3]+S[1]) % v4 == 0)

for i in range(len(S)):
    solver.add(S[i] <= 9)
    solver.add(S[i] >= 0)

num = S[8]
j = 10
for i in reversed(range(8)):
    num += j * S[i]
    j *= 10

solver.add(num % ((num / 100000)+(num % 10000)) == 11**3 + 6)

solver.check()
print solver.model()
