#include <stddef.h>
#include <stdio.h>
void function_null_ptr()
{ // {fact rule=null-pointer-dereference@v1.0 defects=0}
  char *p1 = NULL ;
  if(p1 != NULL && *p1 == '\t') { // Compliant: *p1 cannot be evaluated if p1 is NULL
    p1[2] = '\t';
  }
  // {/fact}

  // {fact rule=null-pointer-dereference@v1.0 defects=0}
  char *p2 = NULL ;
  if(p2 != NULL) {
    // ...
    p2[2] = '\t'; // Compliant: p2 is known to be non-null
  }
  // {/fact}
}
int main_null_ptr(int argc, char *argv[])
{
  printf("hello world \n");
  return 0;
}