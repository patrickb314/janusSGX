#include <sgx-lib.h>
#include <egate.h>

#include <polarssl/net.h>
#include <polarssl/aes.h>
#include <polarssl/dhm.h>
#include <polarssl/pk.h>
#include <polarssl/rsa.h>
#include <polarssl/sha256.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#include "kvstore.h"

#define TABLE_SIZE 347

char *provisioner_hostname = "localhost";
int provisioner_port = 11298;
char *provisioner_key = "-----BEGIN PUBLIC KEY-----\n"
"MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAz+eH4VRDgoUozMJSpDm/\n"
"mmSqKm/WkISDKeLnpbMyaEZc1xH+EcxurQkjOBnw4NoNHQU/gEeNJ2x3BNsB5080\n"
"oR/f9wxUb7sr8osKvCMxWvQSor5Y8qoK4/QGBZv0c5MMcplqpcvl1V4CiPL3gl+q\n"
"2RxxTUKtY3gF5+JIGIXkSczzc70aDe8vVQmV/VTd+zT/v/tFkSawCuFh6eXmrkUp\n"
"/WlqNvhPONrwkfCV2fimtx3+7cldFS+vqdZGtpPnist1XYHnHnT/XjoEQPXLdGNj\n"
"f0AgeGig4nrpB8qpx0TBkFu6MTcAg5gbsNCLdSssM3OpgXrSP/mDQ8nPhNblS2Pr\n"
"9Pr28wWw3MHdzeKK3Bp4074+a7zUw1IbyDb+IZpa4coeNzlEbiYQwXgvJFBw3VRK\n"
"HOPgn+PNIyZdQ3Obzd1fa1OZgi7fActwc1xX4L85k/plKxG9+gFhzCVbFcPaRX4g\n"
"hKNOSDZLq/X7McobajTz8DGcgFiNzJAVoJfORN3mRGC5AgMBAAE=\n"
"-----END PUBLIC KEY-----\n";

char *dict[TABLE_SIZE];

int client_fd;

// based on CRC
int hash (char * str)
{    
    unsigned long int high;

    unsigned long int h = 0;
    while (*str) {
        high = h & 0xf8000000;
        h = h << 5;
        h = h ^ (high >> 27);
        h = h ^ *str;
        str++;
    }
    // TODO check for collisions
    return h % TABLE_SIZE;
}

void enclave_main(egate_t *g, kvstore_cmd_t *cmd)
{
    char * msg;
    int index, strsize;

    /* egate_enclave_init(g); */
	eg_set_default_gate(g);

    switch(cmd->type){
    case KVSTORE_SET:
        index = hash(cmd->key);
        strsize = strlen(cmd->msg) + 1;
        msg = malloc(strsize);
        // copy into the enclave
        copyin(msg, cmd->msg, strsize);
        dict[index] = msg;
        break;

    case KVSTORE_GET:
        index = hash(cmd->key);
        msg = dict[index];
        copyout(cmd->msg, msg, strlen(msg));
        break;

    default:
        eg_printf(g, "This should never happen :(... bye\n");
        eg_exit(g, 1);
    }
	
    eg_exit(g, 0);
}
