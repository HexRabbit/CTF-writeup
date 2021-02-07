#include <linux/bpf.h>
#include <string.h>
#include <unistd.h>

#ifndef __NR_BPF
#define __NR_BPF 321
#endif

#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))
#define u64_to_ptr(u64) ((void *)(u64))
#define LOG_BUF_SIZE 65536

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \
  ((struct bpf_insn){                        \
   .code = CODE,                          \
   .dst_reg = DST,                        \
   .src_reg = SRC,                        \
   .off = OFF,                            \
   .imm = IMM})

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)    \
  ((struct bpf_insn){                    \
   .code = BPF_LD | BPF_DW | BPF_IMM, \
   .dst_reg = DST,                    \
   .src_reg = SRC,                    \
   .off = 0,                          \
   .imm = (__u32)(IMM)}),             \
((struct bpf_insn){                \
 .code = 0,                     \
 .dst_reg = 0,                  \
 .src_reg = 0,                  \
 .off = 0,                      \
 .imm = ((__u64)(IMM)) >> 32})

#define BPF_MOV64_IMM(DST, IMM) BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, IMM)
#define BPF_MOV_REG(DST, SRC) BPF_RAW_INSN(BPF_ALU | BPF_MOV | BPF_X, DST, SRC, 0, 0)
#define BPF_MOV64_REG(DST, SRC) BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, DST, SRC, 0, 0)
#define BPF_MOV_IMM(DST, IMM) BPF_RAW_INSN(BPF_ALU | BPF_MOV | BPF_K, DST, 0, 0, IMM)
#define BPF_RSH_REG(DST, SRC) BPF_RAW_INSN(BPF_ALU64 | BPF_RSH | BPF_X, DST, SRC, 0, 0)
#define BPF_LSH_IMM(DST, IMM) BPF_RAW_INSN(BPF_ALU64 | BPF_LSH | BPF_K, DST, 0, 0, IMM)
#define BPF_ALU64_IMM(OP, DST, IMM) BPF_RAW_INSN(BPF_ALU64 | BPF_OP(OP) | BPF_K, DST, 0, 0, IMM)
#define BPF_ALU64_REG(OP, DST, SRC) BPF_RAW_INSN(BPF_ALU64 | BPF_OP(OP) | BPF_X, DST, SRC, 0, 0)
#define BPF_ALU_IMM(OP, DST, IMM) BPF_RAW_INSN(BPF_ALU | BPF_OP(OP) | BPF_K, DST, 0, 0, IMM)
#define BPF_JMP_IMM(OP, DST, IMM, OFF) BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_K, DST, 0, OFF, IMM)
#define BPF_JMP_REG(OP, DST, SRC, OFF) BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_X, DST, SRC, OFF, 0)
#define BPF_JMP32_REG(OP, DST, SRC, OFF) BPF_RAW_INSN(BPF_JMP32 | BPF_OP(OP) | BPF_X, DST, SRC, OFF, 0)
#define BPF_JMP32_IMM(OP, DST, IMM, OFF) BPF_RAW_INSN(BPF_JMP32 | BPF_OP(OP) | BPF_K, DST, 0, OFF, IMM)
#define BPF_EXIT_INSN() BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define BPF_LD_MAP_FD(DST, MAP_FD) BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)
#define BPF_LD_IMM64(DST, IMM) BPF_LD_IMM64_RAW(DST, 0, IMM)
#define BPF_ST_MEM(SIZE, DST, OFF, IMM) BPF_RAW_INSN(BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, DST, 0, OFF, IMM)
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) BPF_RAW_INSN(BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, DST, SRC, OFF, 0)
#define BPF_STX_MEM(SIZE, DST, SRC, OFF) BPF_RAW_INSN(BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, DST, SRC, OFF, 0)

#define BPF_GET_MAP(fd, idx) \
  BPF_LD_MAP_FD(BPF_REG_1, fd), \
  BPF_MOV64_IMM(BPF_REG_2, idx), \
  BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, -4),  \
  BPF_MOV64_REG(BPF_REG_2, BPF_REG_10), \
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), \
  BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem), \
  BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1), \
  BPF_EXIT_INSN()

char bpf_log_buf[LOG_BUF_SIZE];

int bpf_prog_load(enum bpf_prog_type type,
    const struct bpf_insn *insns, int insn_cnt,
    const char *license)
{
  union bpf_attr attr = {
    .prog_type = type,
    .insns = ptr_to_u64(insns),
    .insn_cnt = insn_cnt,
    .license = ptr_to_u64(license),
    .log_buf = ptr_to_u64(bpf_log_buf),
    .log_size = LOG_BUF_SIZE,
    .log_level = 1,
  };

  return syscall(__NR_BPF, BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_create_map(enum bpf_map_type map_type,
    unsigned int key_size,
    unsigned int value_size,
    unsigned int max_entries,
    unsigned int map_flags)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));

  attr.map_type = map_type;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;
  attr.map_flags = map_flags;

  return syscall(__NR_BPF, BPF_MAP_CREATE, &attr, sizeof(attr));
}

int bpf_lookup_elem(int fd, const void *key, void *value)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key = ptr_to_u64(key),
    .value = ptr_to_u64(value),
  };

  return syscall(__NR_BPF, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_update_elem(int fd, const void *key, const void *value,
    size_t flags)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key = ptr_to_u64(key),
    .value = ptr_to_u64(value),
    .flags = flags,
  };

  return syscall(__NR_BPF, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_delete_elem(int fd, const void *key)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key = ptr_to_u64(key),
    .flags = 0
  };

  return syscall(__NR_BPF, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}
