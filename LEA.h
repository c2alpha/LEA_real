#include <stdint.h>

#define LEA_128_RNDS           24
#define LEA_128_KEY_LEN        16

#define LEA_192_RNDS           28
#define LEA_192_KEY_LEN        24

#define LEA_256_RNDS           32
#define LEA_256_KEY_LEN        32

#define LEA_MAX_RNDS           32
#define LEA_MAX_KEY_LEN        32
#define LEA_BLOCK_LEN          16
#define LEA_RNDKEY_WORD_LEN     6   

#define ROR(W,i)    (((uint32_t)(W)>>(int)(i)) | ((uint32_t)(W)<<(32-(int)(i))))
#define ROL(W,i)    (((uint32_t)(W)<<(int)(i)) | ((uint32_t)(W)>>(32-(int)(i))))
#define BTOW(x)     (((uint32_t)(x)[3] << 24) ^ ((uint32_t)(x)[2] << 16) ^ ((uint32_t)(x)[1] <<  8) ^ ((uint32_t)(x)[0]))
#define WTOB(x, v)  { (x)[3] = (unsigned char)((v) >> 24); (x)[2] = (unsigned char)((v) >> 16); (x)[1] = (unsigned char)((v) >>  8); (x)[0] = (unsigned char)(v); }

#define msb ((uint_least32_t) 0x80000000)
#define lsb ((uint_least32_t) 0x00000001)
#define MASK_WL ((uint_least32_t)0xFFFFFFFF)

typedef struct
{
	unsigned char mk[LEA_MAX_KEY_LEN];
	unsigned char p[160];
	unsigned char c[160];
} LEA_MMT_ECB;

typedef struct
{
	unsigned char mk[LEA_MAX_KEY_LEN];
	unsigned char iv[LEA_BLOCK_LEN];
	unsigned char p[160];
	unsigned char c[160];
} LEA_MMT_CBC, LEA_MMT_CTR;

int LEA_Key_Schedule(uint32_t RndKeys[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN],
					 const unsigned char MasterKey[LEA_MAX_KEY_LEN], const int KeyBytes);

void LEA_Encryption(unsigned char ct[LEA_BLOCK_LEN], const unsigned char pt[LEA_BLOCK_LEN],
					uint32_t RndKeys[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN], const int Nr);

void LEA_Decryption(unsigned char pt[LEA_BLOCK_LEN], const unsigned char ct[LEA_BLOCK_LEN],
					uint32_t RndKeys[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN], const int Nr);	

void ECB_LEA_Enc(unsigned char *ct, const unsigned char *pt,
				 const unsigned char MasterKey[LEA_MAX_KEY_LEN], const int pt_size, const int KeyBytes);

void ECB_LEA_Dec(unsigned char *pt, const unsigned char *ct,
				 const unsigned char MasterKey[LEA_MAX_KEY_LEN], const int ct_size, const int KeyBytes);

void CBC_LEA_Enc(unsigned char *ct, const unsigned char *pt, const unsigned char MasterKey[LEA_MAX_KEY_LEN], 
				 const unsigned char IV[LEA_BLOCK_LEN], const int pt_size, const int KeyBytes);

void CBC_LEA_Dec(unsigned char *pt, const unsigned char *ct, const unsigned char MasterKey[LEA_MAX_KEY_LEN],
				 const unsigned char IV[LEA_BLOCK_LEN], const int ct_size, const int KeyBytes);

void CTR_LEA_Enc(unsigned char *ct, const unsigned char *pt, const unsigned char MasterKey[LEA_MAX_KEY_LEN], 
				 const unsigned char IV[LEA_BLOCK_LEN], const int pt_size, const int KeyBytes);

void CTR_LEA_Dec(unsigned char *ct, const unsigned char *pt, const unsigned char MasterKey[LEA_MAX_KEY_LEN], 
				 const unsigned char IV[LEA_BLOCK_LEN], const int ct_size, const int KeyBytes);
