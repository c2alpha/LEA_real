#define _CRT_SECURE_NO_WARNINGS
#include "LEA.h"
#include "Util.h"

// For KAT test, just change the value of strength and MODE appropriately
#define strength 256
#define MODE 3 // 1=>ECB 2=>CBC 3=>CTR

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

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#if MODE==1
int main()
{
	char fn_req[32]={0,}, fn_rsp[32]={0,};
	FILE *fp_req=NULL, *fp_rsp=NULL;
	unsigned char pt[LEA_BLOCK_LEN]={0,}, ct[LEA_BLOCK_LEN]={0,}, decrypted[LEA_BLOCK_LEN]={0,};
	unsigned char mk[LEA_MAX_KEY_LEN]={0,};// Master key
	int done=0;

	// Create the Reponse file
	sprintf(fn_rsp, "LEA%d(ECB)_KAT.rsp", strength);
	if ((fp_rsp = fopen(fn_rsp, "w")) == NULL)
	{
		printf("Couldn't open <%s> for write\n", fn_rsp);
		return KAT_FILE_OPEN_ERROR;
	}

	sprintf(fn_req, "LEA%d(ECB)KAT.req", strength);
	if ((fp_req = fopen(fn_req, "r")) == NULL)
	{
		printf("Couldn't open <%s> for read\n", fn_req);
		return KAT_FILE_OPEN_ERROR;
	}

	done = 0;
	do {
		// Write on the Response file based on what's in the request file
		// Parameters related to the master key length(16, 24, 32) should be changed by macro
		if (!ReadHex(fp_req, mk, KEY_LEN, "KEY = "))
		{
			done = 1;
			break;
		}
		fprintBstr(fp_rsp, "KEY = ", mk, KEY_LEN);

		if (!ReadHex(fp_req, pt, LEA_BLOCK_LEN, "PT = "))
		{
			printf("ERROR : unable to read 'PT' from <%s>\n", fn_req);
			done = 1;
			return KAT_DATA_ERROR;
		}
		fprintBstr(fp_rsp, "PT = ", pt, LEA_BLOCK_LEN);

		// Generate the ciphertext on response file
		ECB_LEA_Enc(ct, pt, mk, 1<<4, KEY_LEN);
		fprintBstr(fp_rsp, "CT = ", ct, LEA_BLOCK_LEN);

		fprintf(fp_rsp, "\n");

		ECB_LEA_Dec(decrypted, ct, mk, 1<<4, KEY_LEN);
		if (memcmp(decrypted, pt, LEA_BLOCK_LEN))
		{
			printf("Crypto alg fail\n");
			done = 1;
		}


	} while (!done);

	fclose(fp_req);
	fclose(fp_rsp);

	return KAT_SUCCESS;
}

#elif MODE==2
int main()
{
	char fn_req[32]={0,}, fn_rsp[32]={0,};
	FILE *fp_req=NULL, *fp_rsp=NULL;
	unsigned char pt[LEA_BLOCK_LEN]={0,}, ct[LEA_BLOCK_LEN]={0,}, decrypted[LEA_BLOCK_LEN]={0,}, iv[LEA_BLOCK_LEN]={0,};
	unsigned char mk[LEA_MAX_KEY_LEN]={0,};// Master key
	int done=0;

	// Create the Reponse file
	sprintf(fn_rsp, "LEA%d(CBC)_KAT.rsp", strength);
	if ((fp_rsp = fopen(fn_rsp, "w")) == NULL)
	{
		printf("Couldn't open <%s> for write\n", fn_rsp);
		return KAT_FILE_OPEN_ERROR;
	}

	sprintf(fn_req, "LEA%d(CBC)KAT.req", strength);
	if ((fp_req = fopen(fn_req, "r")) == NULL)
	{
		printf("Couldn't open <%s> for read\n", fn_req);
		return KAT_FILE_OPEN_ERROR;
	}

	done = 0;
	do {
		// Write on the Response file based on what's in the request file
		// Parameters related to the master key length(16, 24, 32) should be changed by macro
		if (!ReadHex(fp_req, mk, KEY_LEN, "KEY = "))
		{
			done = 1;
			break;
		}
		fprintBstr(fp_rsp, "KEY = ", mk, KEY_LEN);

		if (!ReadHex(fp_req, mk, LEA_BLOCK_LEN, "IV = "))
		{
			done = 1;
			break;
		}
		fprintBstr(fp_rsp, "IV = ", mk, LEA_BLOCK_LEN);

		if (!ReadHex(fp_req, pt, LEA_BLOCK_LEN, "PT = "))
		{
			printf("ERROR : unable to read 'PT' from <%s>\n", fn_req);
			done = 1;
			return KAT_DATA_ERROR;
		}
		fprintBstr(fp_rsp, "PT = ", pt, LEA_BLOCK_LEN);

		// Generate the ciphertext on response file
		CBC_LEA_Enc(ct, pt, mk, iv, 1<<4, KEY_LEN);
		fprintBstr(fp_rsp, "CT = ", ct, LEA_BLOCK_LEN);

		fprintf(fp_rsp, "\n");

		CBC_LEA_Dec(decrypted, ct, mk, iv, 1<<4, KEY_LEN);
		if (memcmp(decrypted, pt, LEA_BLOCK_LEN))
		{
			printf("Crypto alg fail\n");
			done = 1;
		}


	} while (!done);

	fclose(fp_req);
	fclose(fp_rsp);

	return KAT_SUCCESS;
}

#elif MODE==3
int main()
{
	char fn_req[32]={0,}, fn_rsp[32]={0,};
	FILE *fp_req=NULL, *fp_rsp=NULL;
	unsigned char pt[LEA_BLOCK_LEN]={0,}, ct[LEA_BLOCK_LEN]={0,}, decrypted[LEA_BLOCK_LEN]={0,}, iv[LEA_BLOCK_LEN]={0,};
	unsigned char mk[LEA_MAX_KEY_LEN]={0,};// Master key
	int done=0;

	// Create the Reponse file
	sprintf(fn_rsp, "LEA%d(CTR)_KAT.rsp", strength);
	if ((fp_rsp = fopen(fn_rsp, "w")) == NULL)
	{
		printf("Couldn't open <%s> for write\n", fn_rsp);
		return KAT_FILE_OPEN_ERROR;
	}

	sprintf(fn_req, "LEA%d(CTR)KAT.req", strength);
	if ((fp_req = fopen(fn_req, "r")) == NULL)
	{
		printf("Couldn't open <%s> for read\n", fn_req);
		return KAT_FILE_OPEN_ERROR;
	}

	done = 0;
	do {
		// Write on the Response file based on what's in the request file
		// Parameters related to the master key length(16, 24, 32) should be changed by macro
		if (!ReadHex(fp_req, mk, KEY_LEN, "KEY = "))
		{
			done = 1;
			break;
		}
		fprintBstr(fp_rsp, "KEY = ", mk, KEY_LEN);

		if (!ReadHex(fp_req, mk, LEA_BLOCK_LEN, "CTR = "))
		{
			printf("ERROR : unable to read 'CTR' from <%s>\n", fn_req);
			done = 1;
			break;
		}
		fprintBstr(fp_rsp, "CTR = ", mk, LEA_BLOCK_LEN);

		if (!ReadHex(fp_req, pt, LEA_BLOCK_LEN, "PT = "))
		{
			printf("ERROR : unable to read 'PT' from <%s>\n", fn_req);
			done = 1;
			return KAT_DATA_ERROR;
		}
		fprintBstr(fp_rsp, "PT = ", pt, LEA_BLOCK_LEN);

		// Generate the ciphertext on response file
		CTR_LEA_Enc(ct, pt, mk, iv, 1<<4, KEY_LEN);
		fprintBstr(fp_rsp, "CT = ", ct, LEA_BLOCK_LEN);

		fprintf(fp_rsp, "\n");

		CTR_LEA_Dec(decrypted, ct, mk, iv, 1<<4, KEY_LEN);
		if (memcmp(decrypted, pt, LEA_BLOCK_LEN))
		{
			printf("Crypto alg fail\n");
			done = 1;
		}


	} while (!done);

	fclose(fp_req);
	fclose(fp_rsp);

	return KAT_SUCCESS;
}


#endif
