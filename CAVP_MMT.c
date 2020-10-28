#define _CRT_SECURE_NO_WARNINGS
#include "LEA.h"
#include "Util.h"

/* To do..
 * Consider how can controll arbitrary size input...
 * 
*/

// For MMT test, just change the value of strength and MODE appropriately
#define strength 256
#define MODE 1 // 1=>ECB 2=>CBC 3=>CTR

#if strength==128
#define KEY_LEN LEA_128_KEY_LEN
#define RNDS LEA_128_RNDS

#elif strength==192
#define KEY_LEN LEA_192_KEY_LEN
#define RNDS LEA_192_RNDS

#else
#define KEY_LEN LEA_256_KEY_LEN
#define RNDS LEA_256_RNDS

#endif

#define MAX_MARKER_LEN      50
#define MMT_SUCCESS          0
#define MMT_FILE_OPEN_ERROR -1
#define MMT_DATA_ERROR      -3
#define MMT_CRYPTO_FAILURE  -4

#if MODE==1
int main()
{
	char fn_req[32], fn_rsp[32];
	FILE* fp_req, * fp_rsp;
	LEA_MMT_ECB test_vec_ecb;
	unsigned char decrypted[160];
	int done;
	int iter = 0;
	
	// Create the Reponse file
	sprintf(fn_rsp, "LEA%d(ECB)_MMT.rsp", strength);
	if ((fp_rsp = fopen(fn_rsp, "w")) == NULL)
	{
		printf("Couldn't open <%s> for write\n", fn_rsp);
		return MMT_FILE_OPEN_ERROR;
	}

	sprintf(fn_req, "LEA%d(ECB)MMT.req", strength);
	if ((fp_req = fopen(fn_req, "r")) == NULL)
	{
		printf("Couldn't open <%s> for read\n", fn_req);
		return MMT_FILE_OPEN_ERROR;
	}

	done = 0;
	do {
		// Write on the Response file based on what's in the request file
		// Parameters related to the master key length(16, 24, 32) should be changed by macro
		if (!ReadHex(fp_req, test_vec_ecb.mk, KEY_LEN, "KEY = "))
		{
			done = 1;
			break;
		}
		fprintBstr(fp_rsp, "KEY = ", test_vec_ecb.mk, KEY_LEN);

		if (!ReadHex(fp_req, test_vec_ecb.p, (iter + 1)<<4, "PT = "))
		{
			printf("ERROR : unable to read 'PT' from <%s>\n", fn_req);
			done = 1;
			return MMT_DATA_ERROR;
		}
		fprintBstr(fp_rsp, "PT = ", test_vec_ecb.p, (iter + 1)<<4);

		// Generate the ciphertext on response file
		ECB_LEA_Enc(test_vec_ecb.c, test_vec_ecb.p, test_vec_ecb.mk, (iter + 1)<<4, KEY_LEN);
		fprintBstr(fp_rsp, "CT = ", test_vec_ecb.c, (iter + 1) <<4);

		fprintf(fp_rsp, "\n");

		ECB_LEA_Dec(decrypted, test_vec_ecb.c, test_vec_ecb.mk, (iter + 1)<<4, KEY_LEN);
		if (memcmp(decrypted, test_vec_ecb.p, (iter + 1)<<4))
		{
			printf("Crypto alg fail\n");
			done = 1;
			return MMT_CRYPTO_FAILURE;
		}
		
		iter++;

	} while (!done);

	fclose(fp_req);
	fclose(fp_rsp);

	return MMT_SUCCESS;
}

#elif MODE==2
int main()
{
	char fn_req[32], fn_rsp[32];
	FILE* fp_req, * fp_rsp;
	LEA_MMT_CBC test_vec_cbc;
	unsigned char decrypted[160];
	int done;
	int iter = 0;

	// Create the Reponse file
	sprintf(fn_rsp, "LEA%d(CBC)_MMT.rsp", strength);
	if ((fp_rsp = fopen(fn_rsp, "w")) == NULL)
	{
		printf("Couldn't open <%s> for write\n", fn_rsp);
		return MMT_FILE_OPEN_ERROR;
	}
	
	sprintf(fn_req, "LEA%d(CBC)MMT.req", strength);
	if ((fp_req = fopen(fn_req, "r")) == NULL)
	{
		printf("Couldn't open <%s> for read\n", fn_req);
		return MMT_FILE_OPEN_ERROR;
	}

	done = 0;
	do {
		// Write on the Response file based on what's in the request file
		// Parameters related to the master key length(16, 24, 32) should be changed by macro
		if (!ReadHex(fp_req, test_vec_cbc.mk, KEY_LEN, "KEY = "))
		{
			done = 1;
			break;
		}
		fprintBstr(fp_rsp, "KEY = ", test_vec_cbc.mk, KEY_LEN);

		if (!ReadHex(fp_req, test_vec_cbc.iv, LEA_BLOCK_LEN, "IV = "))
		{
			printf("ERROR : unable to read 'IV' from <%s>\n", fn_req);
			done = 1;
			return MMT_DATA_ERROR;
		}
		fprintBstr(fp_rsp, "IV = ", test_vec_cbc.iv, LEA_BLOCK_LEN);

		if (!ReadHex(fp_req, test_vec_cbc.p, (iter + 1)<<4, "PT = "))
		{
			printf("ERROR : unable to read 'PT' from <%s>\n", fn_req);
			done = 1;
			return MMT_DATA_ERROR;
		}
		fprintBstr(fp_rsp, "PT = ", test_vec_cbc.p, (iter + 1)<<4);

		

		// Generate the ciphertext on response file
		CBC_LEA_Enc(test_vec_cbc.c, test_vec_cbc.p, test_vec_cbc.mk, test_vec_cbc.iv, (iter + 1)<<4, KEY_LEN);
		fprintBstr(fp_rsp, "CT = ", test_vec_cbc.c, (iter + 1) <<4);

		fprintf(fp_rsp, "\n");

		CBC_LEA_Dec(decrypted, test_vec_cbc.c, test_vec_cbc.mk, test_vec_cbc.iv, (iter + 1)<<4, KEY_LEN);
		if (memcmp(decrypted, test_vec_cbc.p, (iter + 1) <<4))
		{
			printf("Crypto alg fail\n");
			done = 1;
			return MMT_CRYPTO_FAILURE;
		}

		iter++;

	} while (!done);

	fclose(fp_req);
	fclose(fp_rsp);

	return MMT_SUCCESS;
}

#elif MODE==3
int main()
{
	char fn_req[32], fn_rsp[32];
	FILE* fp_req, * fp_rsp;
	LEA_MMT_CTR test_vec_ctr;
	unsigned char decrypted[160];
	int done;
	int iter = 0;

	// Create the Reponse file
	sprintf(fn_rsp, "LEA%d(CTR)_MMT.rsp", strength);
	if ((fp_rsp = fopen(fn_rsp, "w")) == NULL)
	{
		printf("Couldn't open <%s> for write\n", fn_rsp);
		return MMT_FILE_OPEN_ERROR;
	}

	sprintf(fn_req, "LEA%d(CTR)MMT.req", strength);
	if ((fp_req = fopen(fn_req, "r")) == NULL)
	{
		printf("Couldn't open <%s> for read\n", fn_req);
		return MMT_FILE_OPEN_ERROR;
	}

	done = 0;
	do {
		// Write on the Response file based on what's in the request file
		// Parameters related to the master key length(16, 24, 32) should be changed by macro
		if (!ReadHex(fp_req, test_vec_ctr.mk, KEY_LEN, "KEY = "))
		{
			done = 1;
			break;
		}
		fprintBstr(fp_rsp, "KEY = ", test_vec_ctr.mk, KEY_LEN);

		if (!ReadHex(fp_req, test_vec_ctr.iv, LEA_BLOCK_LEN, "CTR = "))
		{
			printf("ERROR : unable to read 'IV' from <%s>\n", fn_req);
			done = 1;
			return MMT_DATA_ERROR;
		}
		fprintBstr(fp_rsp, "CTR = ", test_vec_ctr.iv, LEA_BLOCK_LEN);

		if (!ReadHex(fp_req, test_vec_ctr.p, (iter + 1) <<4, "PT = "))
		{
			printf("ERROR : unable to read 'PT' from <%s>\n", fn_req);
			done = 1;
			return MMT_DATA_ERROR;
		}
		fprintBstr(fp_rsp, "PT = ", test_vec_ctr.p, (iter + 1) <<4);



		// Generate the ciphertext on response file
		CTR_LEA_Enc(test_vec_ctr.c, test_vec_ctr.p, test_vec_ctr.mk, test_vec_ctr.iv, (iter + 1)<<4, KEY_LEN);
		fprintBstr(fp_rsp, "CT = ", test_vec_ctr.c, (iter + 1) <<4);

		fprintf(fp_rsp, "\n");

		CTR_LEA_Dec(decrypted, test_vec_ctr.c, test_vec_ctr.mk, test_vec_ctr.iv, (iter + 1)<<4, KEY_LEN);
		if (memcmp(decrypted, test_vec_ctr.p, (iter + 1) <<4))
		{
			printf("Crypto alg fail\n");
			done = 1;
			return MMT_CRYPTO_FAILURE;
		}

		iter++;

	} while (!done);

	fclose(fp_req);
	fclose(fp_rsp);

	return MMT_SUCCESS;
}

#endif

