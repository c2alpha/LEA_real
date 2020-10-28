#include "LEA.h"

typedef struct
{
    unsigned char key[LEA_MAX_KEY_LEN];
    unsigned char p[160];
    unsigned char c[160];
} LEA_MMT_ECB;

typedef struct
{
   unsigned char key[LEA_MAX_KEY_LEN];
   unsigned char iv[LEA_BLOCK_LEN];
   unsigned char p[160];
   unsigned char c[160];
} LEA_MMT_CBC, LEA_MMT_CTR;


int lea_mmt_ecb_test();
int lea_mmt_cbc_test();
int lea_mmt_ctr_test();