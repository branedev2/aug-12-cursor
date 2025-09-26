#include <stdio.h>
#include <limits.h>

struct OptionalInt {
    int has_value;
    int value;
};


// {fact rule=divided-by-zero@v1.0 defects=0}
struct OptionalInt safe_division_by_zero_good1(int a, int b) {
    struct OptionalInt result;

    if ((b == 0) || ((a == INT_MIN) && (b == -1))) {
        result.has_value = 0; // Indicates failure
        return result;
    }

    result.has_value = 1;
    result.value = a / b; 
    return result; // Compliant: check correctly prevents divide-by-zero and signed integer overflows
}

// {/fact}

struct OptionalInt foo_division_by_zero(int a, int b) {
  if (b == 0) {
    a = 1;
  }
  return safe_division_by_zero_good1(a, b);
}

struct OptionalInt foo_division_by_zero_good1(int a, int b) {
  if (b == 0) {
    a = 1;
  }
  return safe_division_by_zero_good1(a, b);
}
// {fact rule=divided-by-zero@v1.0 defects=0}
double foo_division_by_zero_good2(int a, int b) {
  return (double)a / b; // Compliant: replace integer division by floating-point division
}
// {/fact}
