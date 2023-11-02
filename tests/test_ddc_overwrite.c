#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "cheriintrin.h"

/* This test attempts to circumvent the DDC compartmentalization feature by
 * using the existing PCC as a temporary DDC to access a secret pointer beyond
 * the original bounds of the compartment. The address of the secret is
 * expected to be passed as `secret_addr`, and the function will return the
 * value at that address. If the given `secret_addr` is out of the original DDC
 * bounds, and this test does not fail, then we have broken the expected
 * security guarantees of our DDC compartmentalization approach.
 */

int
test_leak(unsigned long long secret_addr)
{
    int secret;
    asm volatile("cvtp c0, %[addr]\n\t"
                 "ldr %w[val], [c0]"
            : [val] "=r"(secret)
            : [addr] "r"(secret_addr)
            : "x0", "memory");
    return secret;
}

int
main()
{
    int* secret = malloc(sizeof(int));
    *secret = 42;
    int val = test_leak((unsigned long long) secret);
    assert(val == *secret);
    free(secret);
    return 0;
}
