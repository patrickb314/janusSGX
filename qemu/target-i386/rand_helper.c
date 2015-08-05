#include "cpu.h"
#include "exec/helper-proto.h"

int fdrandom = -1;
target_ulong helper_rdrand(CPUX86State *env, uint32_t type)
{
    target_ulong data;
    size_t insz = 1 << (type), rdsz;
    CC_SRC = 0;

    if (fdrandom < 0) {
	fdrandom = open("/dev/urandom", O_RDONLY);
    }

    if (fdrandom < 0) {
	fprintf(stderr, "Failed to open random number source /dev/urandom");
	return 0;
    }
   
    rdsz = read(fdrandom, &data, insz);
    fprintf(stdout, "Read %lu random bytes (%lx) from /dev/urandom.\n", rdsz, data);
	
    if (rdsz < insz) {
	return 0;
    }
    
    CC_SRC = CC_C;
    return data;
}
