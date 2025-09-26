// {fact rule=use-of-uninitialized-variable@v1.0 defects=1}
int addition() {
  int x;  // x is not initialized
  return x + 10; // Noncompliant: x has grabage value
}
// {/fact}

// {fact rule=use-of-uninitialized-variable@v1.0 defects=1}
int dereference() {
  int* p; // p is not initialized
  return *p; // Noncompliant: p has garbage value
}
// {/fact}

// {fact rule=use-of-uninitialized-variable@v1.0 defects=1}
int function(int flag, int b) {
  int a;
  if (flag) {
    a = b;
  }
  return a; // Noncompliant: "a" has not been initialized in all paths
}
// {/fact}