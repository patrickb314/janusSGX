// The simplest enclave enter/exit.

#include "test.h"

int val = 10;
static int bssval;
void enclave_main(int *arg)
{
    bssval += val;
    *arg += bssval;

    // exitptr = NULL means right after eenter()
}
