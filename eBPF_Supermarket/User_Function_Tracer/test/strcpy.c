#include <stdlib.h>
#include <string.h>
int main() {
  char *s = "Hello!";
  char *t = malloc(15 * sizeof(char));
  int m = strlen(s);
  memcpy(t, s, m);
  int n = strlen(t);
  int ss = strlen(s) + strlen(t);
  memset(t, 0, n);
  free(t);
  t = malloc(12 * sizeof(char));
  free(t);
  return 0;
}
