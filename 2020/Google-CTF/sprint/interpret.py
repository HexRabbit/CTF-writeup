#!/usr/bin/python3
import re
from pwn import *
context.arch = 'amd64'

compiled = '''
mov r8, 0
mov r9, 0
mov r10, 0
mov r11, 0
mov r12, 0
mov r13, 0
mov r14, 0
mov r15, 0
mov rax, 0
mov rbx, 0
mov rcx, 0
mov rdx, 0
mov rdi, 0
mov rsi, 0
'''

s = '''%1$00038s%3$hn%1$65498s%1$28672s%9$hn
%1$00074s%3$hn%1$65462s%1$*8$s%7$hn
%1$00108s%3$hn%1$65428s%1$1s%6$hn
%1$00149s%3$hn%1$65387s%1$*8$s%1$2s%7$hn
%1$00183s%3$hn%1$65353s%1$1s%6$hn
%1$00218s%3$hn%1$65318s%1$2s%11$hn
%1$00264s%3$hn%1$65272s%1$*10$s%1$*10$s%17$hn
%1$00310s%3$hn%1$65226s%1$28672s%1$*16$s%7$hn
%1$00347s%3$hn%1$65189s%1$*5$s%15$hn
%14$c%1$00419s%2$c%4$s%1$65499s%3$hn
%1$00430s%3$hn%1$65106s%1$*10$s%1$*10$s%13$hn
%1$00468s%3$hn%1$65068s%1$65519s%7$hn
%1$00505s%3$hn%1$65031s%1$*12$s%6$hn
%1$00543s%3$hn%1$64993s%1$65520s%7$hn
%1$00580s%3$hn%1$64956s%1$*5$s%15$hn
%14$c%1$00186s%2$c%4$s%1$00429s%3$hn
%1$00663s%3$hn%1$64873s%1$*12$s%1$*12$s%17$hn
%1$00709s%3$hn%1$64827s%1$28672s%1$*16$s%7$hn
%1$00743s%3$hn%1$64793s%1$1s%6$hn
%1$00789s%3$hn%1$64747s%1$*12$s%1$*10$s%13$hn
%1$00430s%3$hn
%1$00847s%3$hn%1$64689s%1$*10$s%1$1s%11$hn
%10$c%1$64869s%2$c%4$s%1$01549s%3$hn
%1$00922s%3$hn%1$64614s%1$57344s%9$hn
%1$00957s%3$hn%1$64579s%1$0s%11$hn
%1$00993s%3$hn%1$64543s%1$*8$s%7$hn
%1$01030s%3$hn%1$64506s%1$*5$s%13$hn
%12$c%1$00014s%2$c%4$s%1$01051s%3$hn
%1$01185s%3$hn
%1$01129s%3$hn%1$64407s%1$*10$s%1$65535s%11$hn
%1$01170s%3$hn%1$64366s%1$*8$s%1$1s%9$hn
%1$00957s%3$hn
%1$01232s%3$hn%1$64304s%1$*10$s%1$00254s%17$hn
%16$c%1$00014s%2$c%4$s%1$01253s%3$hn
%1$01334s%3$hn
%1$01319s%3$hn%1$64217s%1$5s%23$hn
%1$05081s%3$hn
%1$01368s%3$hn%1$64168s%1$0s%9$hn
%1$01403s%3$hn%1$64133s%1$0s%11$hn
%1$01441s%3$hn%1$64095s%1$61696s%7$hn
%1$01478s%3$hn%1$64058s%1$*5$s%13$hn
%1$01513s%3$hn%1$64023s%1$1s%15$hn
%1$01548s%3$hn%1$63988s%1$0s%23$hn
%1$01593s%3$hn%1$63943s%1$57344s%1$*8$s%7$hn
%1$01630s%3$hn%1$63906s%1$*5$s%17$hn
%16$c%1$00014s%2$c%4$s%1$01651s%3$hn
%1$03479s%3$hn
%1$01723s%3$hn%1$63813s%1$*8$s%1$1s%9$hn
%1$01770s%3$hn%1$63766s%1$*16$s%1$65419s%19$hn
%18$c%1$00053s%2$c%4$s%1$01752s%3$hn
%1$01846s%3$hn%1$63690s%1$65520s%17$hn
%1$02373s%3$hn
%1$01908s%3$hn%1$63628s%1$*16$s%1$65422s%19$hn
%18$c%1$00049s%2$c%4$s%1$01894s%3$hn
%1$01980s%3$hn%1$63556s%1$1s%17$hn
%1$02373s%3$hn
%1$02042s%3$hn%1$63494s%1$*16$s%1$65436s%19$hn
%18$c%1$00050s%2$c%4$s%1$02027s%3$hn
%1$02115s%3$hn%1$63421s%1$16s%17$hn
%1$02373s%3$hn
%1$02177s%3$hn%1$63359s%1$*16$s%1$65428s%19$hn
%18$c%1$00053s%2$c%4$s%1$02159s%3$hn
%1$02253s%3$hn%1$63283s%1$65535s%17$hn
%1$02373s%3$hn
%1$02303s%3$hn%1$63233s%1$0s%15$hn
%1$02338s%3$hn%1$63198s%1$0s%17$hn
%1$02373s%3$hn%1$63163s%1$1s%23$hn
%1$02419s%3$hn%1$63117s%1$*12$s%1$*16$s%13$hn
%1$02457s%3$hn%1$63079s%1$65519s%7$hn
%1$02494s%3$hn%1$63042s%1$*12$s%6$hn
%1$02532s%3$hn%1$63004s%1$65520s%7$hn
%1$02569s%3$hn%1$62967s%1$*5$s%17$hn
%16$c%1$00822s%2$c%4$s%1$01782s%3$hn
%1$02652s%3$hn%1$62884s%1$61440s%1$*12$s%7$hn
%1$02689s%3$hn%1$62847s%1$*5$s%17$hn
%1$02727s%3$hn%1$62809s%1$65519s%7$hn
%1$02764s%3$hn%1$62772s%1$*16$s%6$hn
%1$02802s%3$hn%1$62734s%1$65520s%7$hn
%1$02836s%3$hn%1$62700s%1$0s%6$hn
%1$02874s%3$hn%1$62662s%1$65519s%7$hn
%1$02911s%3$hn%1$62625s%1$*5$s%17$hn
%1$02957s%3$hn%1$62579s%1$*16$s%1$*16$s%17$hn
%1$03003s%3$hn%1$62533s%1$28672s%1$*16$s%7$hn
%1$03040s%3$hn%1$62496s%1$*5$s%17$hn
%16$c%1$00266s%2$c%4$s%1$02809s%3$hn
%1$03120s%3$hn%1$62416s%1$*10$s%1$1s%17$hn
%1$03166s%3$hn%1$62370s%1$61698s%1$*16$s%7$hn
%1$03203s%3$hn%1$62333s%1$*5$s%17$hn
%1$03249s%3$hn%1$62287s%1$*16$s%1$*12$s%17$hn
%16$c%1$00042s%2$c%4$s%1$03242s%3$hn
%1$03329s%3$hn%1$62207s%1$*10$s%1$1s%11$hn
%1$01548s%3$hn
%1$03379s%3$hn%1$62157s%1$0s%15$hn
%1$03414s%3$hn%1$62122s%1$2s%23$hn
%1$01548s%3$hn
%1$03464s%3$hn%1$62072s%1$4s%23$hn
%1$65534s%3$hn
%14$c%1$00014s%2$c%4$s%1$03500s%3$hn
%1$05081s%3$hn
%1$03578s%3$hn%1$61958s%1$*10$s%1$65527s%17$hn
%16$c%1$00014s%2$c%4$s%1$03599s%3$hn
%1$03680s%3$hn
%1$03665s%3$hn%1$61871s%1$3s%23$hn
%1$05081s%3$hn
%1$03714s%3$hn%1$61822s%1$0s%9$hn
%1$03749s%3$hn%1$61787s%1$0s%11$hn
%1$03795s%3$hn%1$61741s%1$*8$s%1$65497s%13$hn
%12$c%1$00014s%2$c%4$s%1$03816s%3$hn
%1$04987s%3$hn
%1$03882s%3$hn%1$61654s%1$4s%15$hn
%1$03917s%3$hn%1$61619s%1$0s%13$hn
%1$03963s%3$hn%1$61573s%1$*12$s%1$*12$s%13$hn
%1$04009s%3$hn%1$61527s%1$*12$s%1$*12$s%13$hn
%1$04055s%3$hn%1$61481s%1$57344s%1$*10$s%7$hn
%1$04092s%3$hn%1$61444s%1$*5$s%17$hn
%1$04139s%3$hn%1$61397s%1$*16$s%1$65419s%19$hn
%18$c%1$00014s%2$c%4$s%1$04160s%3$hn
%1$04632s%3$hn
%1$04238s%3$hn%1$61298s%1$*16$s%1$65422s%19$hn
%18$c%1$00057s%2$c%4$s%1$04216s%3$hn
%1$04318s%3$hn%1$61218s%1$*12$s%1$1s%13$hn
%1$04632s%3$hn
%1$04380s%3$hn%1$61156s%1$*16$s%1$65436s%19$hn
%18$c%1$00057s%2$c%4$s%1$04358s%3$hn
%1$04460s%3$hn%1$61076s%1$*12$s%1$2s%13$hn
%1$04632s%3$hn
%1$04522s%3$hn%1$61014s%1$*16$s%1$65428s%19$hn
%18$c%1$00057s%2$c%4$s%1$04500s%3$hn
%1$04602s%3$hn%1$60934s%1$*12$s%1$3s%13$hn
%1$04632s%3$hn
%1$05081s%3$hn
%1$04675s%3$hn%1$60861s%1$*10$s%1$1s%11$hn
%1$04722s%3$hn%1$60814s%1$*14$s%1$65535s%15$hn
%14$c%1$64693s%2$c%4$s%1$05600s%3$hn
%1$04804s%3$hn%1$60732s%1$61708s%1$*8$s%7$hn
%1$04841s%3$hn%1$60695s%1$*5$s%15$hn
%1$04886s%3$hn%1$60650s%1$59392s%1$*8$s%7$hn
%1$04931s%3$hn%1$60605s%1$*14$s%1$*12$s%6$hn
%1$04972s%3$hn%1$60564s%1$*8$s%1$1s%9$hn
%1$03749s%3$hn
%1$05032s%3$hn%1$60504s%1$59392s%1$*8$s%7$hn
%1$05066s%3$hn%1$60470s%1$0s%6$hn
%1$65534s%3$hn
%1$05119s%3$hn%1$60417s%1$59392s%7$hn
%1$05153s%3$hn%1$60383s%1$0s%6$hn
%1$65534s%3$hn
'''

pc = 0
for now in s.split('\n'):
    compiled += f'L{pc}:'
    cnt = 0
    for sub_str in now.split('%')[1:]:
        reg_idx, length_idx, length, action = re.match('^([0-9]*\$)?(\*[0-9]*\$)?([0-9]*)?([schn]*)', sub_str).groups()
        reg_idx = int(reg_idx[:-1])

        if action[-1] == 's':
            if length_idx:
                # *???$
                idx = int(length_idx[1:-1])
                # access stack registers
                if idx >= 8:
                    if idx % 2:
                        raise
                    else:
                        reg_num = (idx-8)//2
                        # compiled += f'movzx stack_reg{reg_num}, stack_reg{reg_num}w\n'
                        cnt = f'{cnt}+stack_reg{reg_num}'
                # access *ptr
                elif idx == 5:
                    compiled += 'mov tmpw, WORD PTR [ptr]\n'
                    cnt = f'{cnt}+tmp'
                # access ptr
                elif idx == 6:
                    raise NotImplemented
                # access &ptr
                elif idx == 7:
                    raise NotImplemented
                else:
                    raise NotImplemented
            elif length:
                if type(cnt) == int:
                    cnt = (cnt + int(length)) & 0xffff
                else:
                    cnt = f'{cnt}+{int(length)}'
            else:
                if reg_idx == 4:
                    # fix it on %hn part
                    cnt = f'{cnt}+BRANCH'
                else:
                    raise NotImplemented

        elif action[-1] == 'c':
            if reg_idx >= 8:
                reg_num = (reg_idx-8)//2
                compiled += f'test stack_reg{reg_num}b, stack_reg{reg_num}b\n'
            if type(cnt) == int:
                cnt = (cnt + 1) & 0xffff
            else:
                cnt += '+1'

        elif action[-1] == 'n':
            if type(cnt) == str:
                if reg_idx == 3:
                    # %14$c%1$00419s%2$c%4$s%1$65499s%3$hn
                    # if 14$ != 0:
                    #     # %2$c will put a \0 on output buffer so %4$s outputs 420 bytes
                    #     jmp 1(%14$c) + 419(%1$00419s) + 1(%2$c) + 420(%4$s) + 65499
                    # else:
                    #     jmp 1 + 419 + 1 + 0 + 65499
                    matched = re.match('([0-9]*)\+BRANCH\+([0-9]*)', cnt)
                    if matched:
                        a, b = matched.groups()
                        set_pc = f'jnz L{(int(a)*2-1+int(b)) & 0xffff}\n' # TRUE
                        # set_pc = f'jz L{(int(a)+int(b)) & 0xffff}\n' # FALSE always fall through
                    else:
                        set_pc = f'FIX PC = {cnt}\n' # manually deal with this case

                # access ptr
                elif reg_idx == 6:
                    compiled += f'lea tmp, [{cnt}]\n'
                    compiled += f'mov WORD PTR [ptr], tmpw\n'

                # access &ptr
                elif reg_idx == 7:
                    compiled += f'lea ptr, [{cnt}]\n'

                # access stack registers
                elif reg_idx >= 8:
                    reg_num = (reg_idx-8)//2
                    if reg_idx % 2:
                        compiled += f'lea stack_reg{reg_num}, [{cnt}]\n'
                        compiled += f'movzx stack_reg{reg_num}, stack_reg{reg_num}w\n'
                    else:
                        compiled += f'lea tmp, [{cnt}]\n'
                        compiled += f'mov WORD PTR [stack_reg{reg_num}], tmpw\n'
                else:
                    compiled += f'FIX {reg_idx=} = {cnt}\n'
            else:
                if reg_idx == 3:
                    set_pc = f'jmp L{cnt}\n'
                elif reg_idx == 6:
                    compiled += f'mov WORD PTR [ptr], {cnt}\n'
                elif reg_idx == 7:
                    compiled += f'mov ptr, {cnt}\n'
                elif reg_idx >= 8:
                    reg_num = (reg_idx-8)//2
                    if reg_idx % 2:
                        compiled += f'mov stack_reg{reg_num}w, {cnt & 0xffff}\n'
                    else:
                        compiled += f'mov WORD PTR [stack_reg{reg_num}], {cnt & 0xffff}\n'
                else:
                    compiled += f'FIX {reg_idx=} = {cnt}\n'
        else:
            raise NotImplemented
    compiled += set_pc
    pc += len(now) + 1

compiled += '''
L65534:
ret
'''

compiled = compiled.replace('stack_reg0', 'r8')
compiled = compiled.replace('stack_reg1', 'r9')
compiled = compiled.replace('stack_reg2', 'r10')
compiled = compiled.replace('stack_reg3', 'r11')
compiled = compiled.replace('stack_reg4', 'r12')
compiled = compiled.replace('stack_reg5', 'r13')
# compiled = compiled.replace('stack_reg6', 'r14') not used
compiled = compiled.replace('stack_reg7', 'r14')
compiled = compiled.replace('tmp', 'r15')
compiled = compiled.replace('ptr', 'rax')

assert(not 'FIX' in compiled)
open('./compiled', 'wb').write(make_elf(asm(compiled)))
