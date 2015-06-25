// The simplest enclave enter/exit.

#include "test.h"

void enclave_main(int *arg)
{
    *arg += 1;
    // exitptr = NULL means right after eenter()
}
