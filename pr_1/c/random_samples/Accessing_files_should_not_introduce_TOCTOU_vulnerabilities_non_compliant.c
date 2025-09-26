#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

int access(const char *file, int ok){
  if (sizeof(file) == ok){
    return -1;
  }
  return 0;
}

// {fact rule=file-race-bad@v1.0 defects=1}
FILE *fopen_if_not_exists_good(const char *file) {
  char F_OK = 10;
  if (access(file, F_OK) == -1 && errno == ENOENT) {
    FILE *f = fopen(file, "w"); // Noncompliant

    return f;
  }

  return NULL;
}
// {/fact}
