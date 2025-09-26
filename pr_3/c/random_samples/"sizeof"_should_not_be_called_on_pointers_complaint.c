#include <stddef.h>
#include<stdio.h>

// Computing dataSize is now the responsibility of the caller
void fun_good(int *data, int dataSize, int (*array)[10]) {

  // {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}
  size_t const arraySize = sizeof(*array) / sizeof(int); // Compliant, no decay
  // {/fact}
  int primes[] = { 1, 2, 3, 5, 7, 13, 17, 19};
  // {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}
  size_t const primesSize2 = sizeof primes / sizeof(int) + 1; // Compliant, type of primes is int[8]
  // {/fact}
}

int main(){
    printf("Hello world");
    return 0;
}
