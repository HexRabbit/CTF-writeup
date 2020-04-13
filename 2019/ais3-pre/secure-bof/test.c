#include <time.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  int i = 0;
  unsigned char s2[50];
  srand(time(0) + atoi(argv[1]));

  for ( i = 0; i <= 15; ++i )
      s2[i] = rand();

  for (int i = 0; i < 16; ++i) {
    printf("%d ", s2[i]);
  }
}
