JanusSGX: A modification of OpenSGX for developing new enclave
APIs. Most of the original old OpenSGX runtime, which relies on 
non-standard hardware behavior, has been stripped away and things
are closer to what real hardware will need.

Quickstart Build Instructions
=============================

1. Build qemu: 

        (cd qemu; ./configure-arch; make)

2. Build libsgx and mbedtls (currently using stock mbed TLS 1.3.11)

        make -C libsgx

3. Build rest of enclave fake kernel/user runtime/enclave runtime/example enclave and test code:

        make -C user

4. Generate a local key for signing enclaves:

         ./opensgx -k

5. Run a simple enclave test using a fake sigstruct/einittoken that is signs using the user/conf/test.key key and a pre-known launch key:

        cd user
        ../opensgx ./sgx-test ./test/simple-arg.sgx

5. Use this key to sign the sigstruct of the test case above using the GT tools (generates user/test/simple-arg.conf, uses a pre-set launch key for making the einittoken)

        ../opensgx -s test/simple-arg.sgx --key ../sign.key

6. Run using this actual sigstruct and einittokey:

        ../opensgx sgx-test test/simple-arg.sgx test/simple-arg.conf

7. Sign the launch enclave with the "intel" key so it can start up and use egetkey to access the processor launch key:

        ../opensgx -s bootstrap/launch-enclave.sgx -I

8. Run the launch enclave to verify we can generate a proper launch token for a sigstruct using egetkey/etc.

        ../opensgx launch-test bootstrap/launch-enclave.sgx bootstrap/launch-enclave.conf conf/intel.key test/simple-arg.conf
        # Generated einittoken MAC should match what the GT user tools generated with the launch key they'd extracted/generated using by knowing the "hardware fuses".

Debugging JanusSGX Programs
===========================

To debug enclave code in JanusSGX, you can use the qemu linux-user GDB stub and GDB
remote debugging support. In addition to normal remote GDB commands, you will also
want to load symbols for the (runtime-loaded) enclave code. Below is a simple example:

1. Run the test program with remote GDB support in the background:

        ../opensgx -d 1234 sgx-test test/simple-arg.sgx test/simple-arg.conf &

2. Run, attach GDB to the emulator, and set a breakpoint immediately prior to launching the enclave

        gdb sgx-test
        (gdb) target remote localhost:1234
        (gdb) break create_enclave_conf
        (gdb) c

3. Because the enclave code is loaded separately, you must explicitly tell GDB about symbols in it for it to be able to backtrace and debug enclave code. Note that the sgx-test program is configured to print out the gdb command that you need to run to do this.
        (gdb) add-symbol-file test/simple-arg.sgx 0x5000010c
        (gdb) c

At this point, any errors in the program can be backtraced, and enclave state 
debugged. Breakpoints in enclave code are not necessarily fully functional, however.

OpenSGX: An open platform for Intel SGX
=======================================

Contribution Guides
-------------------
- coding style
- make sure all the test/unit cases pass
- license

Environments & Prerequisites
----------------------------
- Tested: Ubuntu 14.04-15.04, Arch
- Requisite: 
  - Ubuntu: apt-get build-dep qemu
  - Fedora: yum-builddep qemu

~~~~~{.sh}
$ cd qemu
$ ./configure-arch
$ make -j $(nproc)

$ cd ..
$ make
~~~~~

Run your first OpenSGX program
------------------------------

- Take user/demo/hello.c as an example.

~~~~~{.c}
#include <sgx-lib.h>

void enclave_main()
{
    char *hello = "hello sgx"\n";
    sgx_puts(hello);
    sgx_exit(NULL);
}
~~~~~

~~~~~{.sh}
$ ./opensgx -k
generate sign.key
$ ./opensgx -c user/demo/hello.c
generate hello.sgx
$ ./opensgx -s user/demo/hello.sgx --key sign.key
generate hello.conf
$ ./opensgx user/demo/hello.conf
run the program
~~~~~

Testing
-------

~~~~~{.sh}
$ cd user
$ ./test.sh test/simple
...
$ ./test.sh --help
[usage] ./test.sh [option]... [binary]
-a|--all  : test all cases
-h|--help : print help
-i|--instuct-test : run an instruction test
-ai|--all-instruction-tests  : run all instruction test cases
--perf|--performance-measure : measure SGX emulator performance metrics
[test]
 test/exception-div-zero.c     :  An enclave test case for divide by zero exception.
 test/fault-enclave-access.c   :  An enclave test case for faulty enclave access.
 test/simple-aes.c             :  An enclave test case for simple encryption/decryption using openssl library.
 test/simple-attest.c          :  test network send
 test/simple.c                 :  The simplest enclave enter/exit.
 test/simple-func.c            :  The simplest function call inside the enclave.
 test/simple-getkey.c          :  hello world
 test/simple-global.c          :  The simplest enclave which accesses a global variable
 test/simple-hello.c           :  Hello world enclave program.
 test/simple-network.c         :  test network recv
 test/simple-openssl.c         :  test openssl api
 test/simple-quote.c           :  test network recv
 test/simple-recv.c            :  An enclave test case for sgx_recv.
 test/simple-send.c            :  An enclave test case for sgx_send.
 test/simple-sgxlib.c          :  An enclave test case for sgx library.
 test/simple-stack.c           :  The simplest enclave enter/exit with stack.
 test/stub.c                   :  An enclave test case for stub & trampoline interface.
 test/stub-malloc.c            :  An enclave test case for using heap
 test/stub-realloc.c           :  An enclave test case for sgx_realloc
~~~~~

Pointers
--------

- QEMU side
    - qemu/target-i386/helper.h    : Register sgx helper functions (sgx_encls, sgx_enclu, ...).
    - qemu/target-i386/cpu.h       : Add sgx-specific cpu registers (see refs-rev2 5.1.4).
    - qemu/target-i386/translate.c : Emulates enclave mode memory access semantics.
    - qemu/target-i386/sgx.h       : Define sgx and related data structures.
    - qemu/target-i386/sgx-dbg.h   : Define debugging function.
    - qemu/target-i386/sgx-utils.h : Define utils functions.
    - qemu/target-i386/sgx-perf.h  : Perforamce evaluation.
    - qemu/target-i386/sgx_helper.c: Implement sgx instructions.

- User side
    - user/sgx-kern.c         : Emulates kernel-level functions.
    - user/sgx-user.c         : Emulates user-level functions.
    - user/sgxLib.c           : Implements user-level API.
    - user/sgx-utils.c        : Implements utils functions.
    - user/sgx-signature.c    : Implements crypto related functions.
    - user/sgx-runtime.c      : sgx runtime.
    - user/sgx-test-runtime.c : sgx runtime for test cases.
    - user/include/ : Headers.
    - user/conf/    : Configuration files.
    - user/test/    : Test cases.
    - user/demo/    : Demo case.

Contact
-------

Email: [OpenSGX team](sgx@cc.gatech.edu).

Authors
-------

- Prerit Jain <pjain43@gatech.edu>
- Soham Desai <sdesai1@gatech.edu>
- Seongmin Kim <dallas1004@gmail.com>
- Ming-Wei Shih <mingwei.shih@gatech.edu>
- JaeHyuk Lee <jhl9105@kaist.ac.kr>
- Changho Choi <zpzigi@kaist.ac.kr>
- Taesoo Kim <taesoo@gatech.edu>
- Dongsu Han <dongsu.han@gmail.com>
- Brent Kang <brentkang@gmail.com>

NOTE. All authors at Gatech and KAIST equally contributed to the project
