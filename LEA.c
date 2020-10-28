#include <stdio.h>
#include "LEA.h"

const uint32_t delta[8] = { 0xc3efe9db,0x44626b02,0x79e27c8a,0x78df30ec,
                            0x715ea49e,0xc785da0a,0xe04ef22a,0xe5c40957 };

/*
* Description : Key schedule in LEA
* Require     : Master secret key which length is 128, 192, 256 bits for LEA-128, LEA-192, LEA-256 respectively
* Ensure      : Round keys which has 24, 28, 32 rounds for LEA-128, LEA-192, LEA-256 respectively
*
* Return value is number of rounds. If there is an error, it returns -1
*/
int LEA_Key_Schedule(uint32_t RndKeys[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN], 
                     const unsigned char MasterKey[LEA_MAX_KEY_LEN], const int KeyBytes)
{
    uint32_t T[8] = { 0x0, };
    int i=0;

    if (RndKeys == NULL || MasterKey == NULL)
        return -1;
    if (KeyBytes != 16 && KeyBytes != 24 && KeyBytes != 32)
        return -1;
    
    if (KeyBytes == LEA_128_KEY_LEN)//LEA-128
    {
        T[0] = BTOW(MasterKey);
        T[1] = BTOW(MasterKey + 4);
        T[2] = BTOW(MasterKey + 8);
        T[3] = BTOW(MasterKey + 12);
        for (i = 0; i < LEA_128_RNDS; i++)
        {
            T[0] = ROL(T[0] + ROL(delta[i & 3], i), 1);
            T[1] = ROL(T[1] + ROL(delta[i & 3], i + 1), 3);
            T[2] = ROL(T[2] + ROL(delta[i & 3], i + 2), 6);
            T[3] = ROL(T[3] + ROL(delta[i & 3], i + 3), 11);

            RndKeys[i][0] = T[0];
            RndKeys[i][1] = T[1];
            RndKeys[i][2] = T[2];
            RndKeys[i][3] = T[1];
            RndKeys[i][4] = T[3];
            RndKeys[i][5] = T[1];
        }
        
        return LEA_128_RNDS;
    }

    else if (KeyBytes == LEA_192_KEY_LEN)//LEA-192
    {
        T[0] = BTOW(MasterKey);
        T[1] = BTOW(MasterKey + 4);
        T[2] = BTOW(MasterKey + 8);
        T[3] = BTOW(MasterKey + 12);
        T[4] = BTOW(MasterKey + 16);
        T[5] = BTOW(MasterKey + 20);

        for (i = 0; i < LEA_192_RNDS; i++)
        {
            // Shift 32 is same with shift 0 so we use &1f for mod32
            T[0] = ROL(T[0] + ROL(delta[i % 6], i & 0x1f), 1);
            T[1] = ROL(T[1] + ROL(delta[i % 6], (i + 1) & 0x1f), 3);
            T[2] = ROL(T[2] + ROL(delta[i % 6], (i + 2) & 0x1f), 6);
            T[3] = ROL(T[3] + ROL(delta[i % 6], (i + 3) & 0x1f), 11);
            T[4] = ROL(T[4] + ROL(delta[i % 6], (i + 4) & 0x1f), 13);
            T[5] = ROL(T[5] + ROL(delta[i % 6], (i + 5) & 0x1f), 17);

            RndKeys[i][0] = T[0];
            RndKeys[i][1] = T[1];
            RndKeys[i][2] = T[2];
            RndKeys[i][3] = T[3];
            RndKeys[i][4] = T[4];
            RndKeys[i][5] = T[5];
        }

        return LEA_192_RNDS;
    }

    else if (KeyBytes == LEA_256_KEY_LEN)//LEA-256
    {
        T[0] = BTOW(MasterKey);
        T[1] = BTOW(MasterKey + 4);
        T[2] = BTOW(MasterKey + 8);
        T[3] = BTOW(MasterKey + 12);
        T[4] = BTOW(MasterKey + 16);
        T[5] = BTOW(MasterKey + 20);
        T[6] = BTOW(MasterKey + 24);
        T[7] = BTOW(MasterKey + 28);

        for (i = 0; i < LEA_256_RNDS; i++)
        {
            T[(6 * i) & 7] = ROL(T[(6 * i) & 7] + ROL(delta[i & 7], i & 0x1f), 1);
            T[(6 * i + 1) & 7] = ROL(T[(6 * i + 1) & 7] + ROL(delta[i & 7], (i + 1) & 0x1f), 3);
            T[(6 * i + 2) & 7] = ROL(T[(6 * i + 2) & 7] + ROL(delta[i & 7], (i + 2) & 0x1f), 6);
            T[(6 * i + 3) & 7] = ROL(T[(6 * i + 3) & 7] + ROL(delta[i & 7], (i + 3) & 0x1f), 11);
            T[(6 * i + 4) & 7] = ROL(T[(6 * i + 4) & 7] + ROL(delta[i & 7], (i + 4) & 0x1f), 13);
            T[(6 * i + 5) & 7] = ROL(T[(6 * i + 5) & 7] + ROL(delta[i & 7], (i + 5) & 0x1f), 17);

            RndKeys[i][0] = T[(6 * i) & 7];
            RndKeys[i][1] = T[(6 * i + 1) & 7];
            RndKeys[i][2] = T[(6 * i + 2) & 7];
            RndKeys[i][3] = T[(6 * i + 3) & 7];
            RndKeys[i][4] = T[(6 * i + 4) & 7];
            RndKeys[i][5] = T[(6 * i + 5) & 7];
        }

        return LEA_256_RNDS;
    }

    return -1;

}

/*
* Description : Encryption primitive
* Require     : 128 bits plain text and round keys. Length of round keys depend on Nr which is number of rounds
* Ensure      : 128 bits cipher text
*/
void LEA_Encryption(unsigned char ct[LEA_BLOCK_LEN], const unsigned char pt[LEA_BLOCK_LEN],
                    uint32_t RndKeys[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN], const int Nr)
{
    uint32_t X0=0, X1=0, X2=0, X3=0;
    uint32_t temp=0;
    int i=0;

    if (RndKeys == NULL || ct == NULL || pt==NULL)
        return;
    if (Nr != 24 && Nr != 28 && Nr != 32)
        return;

    X0 = BTOW(pt);
    X1 = BTOW(pt + 4);
    X2 = BTOW(pt + 8);
    X3 = BTOW(pt + 12);


    for (i = 0; i < Nr; i++)
    {
        temp = X0;
        X0 = ROL((X0 ^ RndKeys[i][0]) + (X1 ^ RndKeys[i][1]), 9);
        X1 = ROR((X1 ^ RndKeys[i][2]) + (X2 ^ RndKeys[i][3]), 5);
        X2 = ROR((X2 ^ RndKeys[i][4]) + (X3 ^ RndKeys[i][5]), 3);
        X3 = temp;
    }

    WTOB(ct, X0);
    WTOB(ct + 4, X1);
    WTOB(ct + 8, X2);
    WTOB(ct + 12, X3);
}

/*
* Description : Decrytion primitive
* Require     : 128 bits cipher text and round keys. Length of round keys depend on Nr which is number of rounds
* Ensure      : 128 bits plain text
*/
void LEA_Decryption(unsigned char pt[LEA_BLOCK_LEN], const unsigned char ct[LEA_BLOCK_LEN],
                    uint32_t RndKeys[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN], const int Nr)
{
    uint32_t X0=0, X1=0, X2=0, X3=0;
    uint32_t temp0=0, temp1=0, temp2=0;
    int i=0;

    if (RndKeys == NULL || ct == NULL || pt == NULL)
        return;
    if (Nr != 24 && Nr != 28 && Nr != 32)
        return;

    X0 = BTOW(ct);
    X1 = BTOW(ct + 4);
    X2 = BTOW(ct + 8);
    X3 = BTOW(ct + 12);

    for (i = 0; i < Nr; i++)
    {
        temp0 = X0;
        temp1 = X1;
        temp2 = X2;
        X0 = X3;
        X1 = (ROR(temp0, 9) - (X0 ^ RndKeys[Nr - 1 - i][0])) ^ RndKeys[Nr - 1 - i][1];
        X2 = (ROL(temp1, 5) - (X1 ^ RndKeys[Nr - 1 - i][2])) ^ RndKeys[Nr - 1 - i][3];
        X3 = (ROL(temp2, 3) - (X2 ^ RndKeys[Nr - 1 - i][4])) ^ RndKeys[Nr - 1 - i][5];

    }

    WTOB(pt, X0);
    WTOB(pt + 4, X1);
    WTOB(pt + 8, X2);
    WTOB(pt + 12, X3);
}

/*
* Description : Encryption using ECB mode
* Require     : Parameters that needed for using Key schedule and Encryption.
*               pt_size is number of total bytes of 128-bit plain texts
* Ensure      : pt_size cipher texts
*/
void ECB_LEA_Enc(unsigned char *ct, const unsigned char *pt,
                 const unsigned char MasterKey[LEA_MAX_KEY_LEN], const int pt_size, const int KeyBytes)
{
    uint32_t RK[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN]={0,};
    int LEA_Rounds=0; 
    int num_Blocks=0;

    if(pt_size&0xf)//In ECB mode input plain texts can not contain partial block
        return;

    if(MasterKey==NULL || pt==NULL || ct==NULL)
        return;

    if(KeyBytes!=16 && KeyBytes!=24 && KeyBytes!=32)
        return;

    

    LEA_Rounds= LEA_Key_Schedule(RK, MasterKey, KeyBytes);
    num_Blocks = pt_size >> 4;

    for (int i = 0; i < num_Blocks; i++)
    {
        LEA_Encryption(ct + (i <<4), pt + (i <<4), RK, LEA_Rounds);
    }

}

/*
* Description : Decryption using ECB mode
* Require     : Parameters that needed for using Key schedule and Decryption. 
*               ct_size is number of total bytes of 128-bit cipher texts
* Ensure      : ct_size plain texts
*
*/
void ECB_LEA_Dec(unsigned char *pt, const unsigned char *ct,
                 const unsigned char MasterKey[LEA_MAX_KEY_LEN], const int ct_size, const int KeyBytes)
{
    uint32_t RK[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN]={0,};
    int LEA_Rounds=0;
    int num_Blocks=0;

    if(ct_size&0xf)
        return;

    if (MasterKey == NULL || pt == NULL || ct == NULL)
        return;

    if(KeyBytes!=16 && KeyBytes!=24 && KeyBytes!=32)
        return;

    LEA_Rounds = LEA_Key_Schedule(RK, MasterKey, KeyBytes);
    num_Blocks = ct_size >> 4;

    for (int i = 0; i < num_Blocks; i++)
    {
        LEA_Decryption(pt + (i <<4), ct + (i <<4), RK, LEA_Rounds);
    }

}

/*
* Description : Encryption using CBC mode
* Require     : Parameters that needed for using Key schedule and Encryption. 
*               pt_size is number of total bytes of 128-bit plain texts. 16-bytes initialize vector.
* Ensure      : pt_size cipher texts
*/
void CBC_LEA_Enc(unsigned char *ct, const unsigned char *pt, const unsigned char MasterKey[LEA_MAX_KEY_LEN],
                 const unsigned char IV[LEA_BLOCK_LEN], const int pt_size, const int KeyBytes)
{
    uint32_t RK[LEA_MAX_KEY_LEN][LEA_RNDKEY_WORD_LEN]={0,};
    int i=0,j=0;
    unsigned char X[LEA_BLOCK_LEN]={0,};
    int LEA_Rounds=0;
    int num_Blocks=0;
 
    if(pt_size&0xf)//In CBC mode input plain texts can not contain partial block
        return;

    if (MasterKey == NULL || pt == NULL || ct == NULL)
        return;

    if(KeyBytes!=16 && KeyBytes!=24 && KeyBytes!=32)
        return;
    
    LEA_Rounds= LEA_Key_Schedule(RK, MasterKey, KeyBytes);
    num_Blocks = pt_size >> 4;

    for(i=0;i<LEA_BLOCK_LEN; i++)
        X[i]=pt[i]^IV[i];

    LEA_Encryption(ct,X,RK,LEA_Rounds);

    for(i=1; i<num_Blocks; i++)
    {
        for(j=0; j<LEA_BLOCK_LEN; j++)
            X[j]=pt[(i<<4)+j]^ct[((i-1)<<4)+j];

        LEA_Encryption(ct+(i<<4), X, RK, LEA_Rounds);
    }
}

/*
* Description : Decryption using CBC mode
* Require     : Parameters that needed for using Key schedule and Decryption. 
*               ct_size is number of total bytes of 128-bit plain texts. 16-bytes initialize vector.
* Ensure      : ct_size plain texts
*/
void CBC_LEA_Dec(unsigned char *pt, const unsigned char *ct, const unsigned char MasterKey[LEA_MAX_KEY_LEN],
                 const unsigned char IV[LEA_BLOCK_LEN], const int ct_size, const int KeyBytes)
{
     uint32_t RK[LEA_MAX_KEY_LEN][LEA_RNDKEY_WORD_LEN]={0,};
     int i=0,j=0;
     unsigned char X[LEA_BLOCK_LEN]={0,};
     int LEA_Rounds=0;
     int num_Blocks=0;

    if(ct_size&0xf)
       return;
    
    if (MasterKey == NULL || pt == NULL || ct == NULL)
        return;

    if(KeyBytes!=16 && KeyBytes!=24 && KeyBytes!=32)
        return;
     
    LEA_Rounds = LEA_Key_Schedule(RK, MasterKey, KeyBytes);
    num_Blocks = ct_size >> 4;

    LEA_Decryption(X,ct,RK,LEA_Rounds);

    for(i=0;i<LEA_BLOCK_LEN; i++)
        pt[i]=X[i]^IV[i];

    for(i=1; i<num_Blocks; i++)
    {
        LEA_Decryption(X,ct+(i<<4),RK,LEA_Rounds);
        for(j=0; j<LEA_BLOCK_LEN; j++)
            pt[(i<<4)+j]=X[j]^ct[((i-1)<<4)+j];
    }
}

/*
* Description : Encryption using CTR mode
* Require     : Parameters that needed for using Key schedule and Encryption. 
*               pt_size is number of total bytes of 128-bit plain texts. 16-bytes initialize vector.
* Ensure      : pt_size cipher texts
*/
void CTR_LEA_Enc(unsigned char *ct, const unsigned char *pt, const unsigned char MasterKey[LEA_MAX_KEY_LEN],
                 const unsigned char IV[LEA_BLOCK_LEN], const int pt_size, const int KeyBytes)
{
    uint32_t RK[LEA_MAX_KEY_LEN][LEA_RNDKEY_WORD_LEN]={0,};
    int i=0, j=0;
    unsigned char CTR[LEA_BLOCK_LEN]={0,};
    unsigned char Y[LEA_BLOCK_LEN]={0,};
    int n=0;
    int flag = 1;
    int LEA_Rounds=0;
    // Make number of blocks and remain chars
    int num_Blocks=0;
    int remain_chars=0;
    
    if (MasterKey == NULL || pt == NULL || ct == NULL)
        return;

    if(KeyBytes!=16 && KeyBytes!=24 && KeyBytes!=32)
        return;

    LEA_Rounds = LEA_Key_Schedule(RK, MasterKey, KeyBytes);
    num_Blocks = pt_size >> 4;
    remain_chars = pt_size & 0xf;

    for (i = 0; i < LEA_BLOCK_LEN; i++)
        CTR[i] = IV[i];

    for (i = 0; i < num_Blocks; i++)
    {
        LEA_Encryption(Y, CTR, RK, LEA_Rounds);
        for (j = 0; j < LEA_BLOCK_LEN; j++)
        {
            ct[(i << 4) + j] = pt[(i << 4) + j] ^ Y[j];
        }
        
        for (n = 15; n >= 0; n--)
        {
            CTR[n]++;
            if (CTR[n])
                break;
        }

        // If CTR is out of range, treat as an error
        for (n = 0; n < 16; n++)
        {
            if (CTR[n] != 0)
            {
                flag = 0;
                break;
            }
        }
        if (flag)
            return;
    }

    if (remain_chars)
    {
        LEA_Encryption(Y, CTR, RK, LEA_Rounds);
        for ( i = 0; i < remain_chars; i++)
        {
            ct[(num_Blocks << 4) + i] = pt[(num_Blocks << 4) + i] ^ Y[i];
        }
    }
}

/*
* Description : Decryption using CTR mode
* Require     : Parameters that needed for using Key schedule and Decryption. 
*               ct_size is number of total chars of 128-bit plain text. 16-bytes initialize vector.
* Ensure      : ct_size plain texts
*/
void CTR_LEA_Dec(unsigned char *pt, const unsigned char *ct, const unsigned char MasterKey[LEA_MAX_KEY_LEN], 
                 const unsigned char IV[LEA_BLOCK_LEN], const int ct_size, const int KeyBytes)
{
    uint32_t RK[LEA_MAX_KEY_LEN][LEA_RNDKEY_WORD_LEN]={0,};
    int i=0, j=0;
    unsigned char CTR[LEA_BLOCK_LEN]={0,};
    unsigned char Y[LEA_BLOCK_LEN]={0,};
    int n=0;
    int flag = 1;
    int LEA_Rounds=0;
    // Make number of blocks and remain chars
    int num_Blocks=0; 
    int remain_chars=0; 
    

    if (MasterKey == NULL || pt == NULL || ct == NULL)
        return;

    if(KeyBytes!=16 && KeyBytes!=24 && KeyBytes!=32)
        return;

    LEA_Rounds = LEA_Key_Schedule(RK, MasterKey, KeyBytes);
    num_Blocks = ct_size >> 4;
    remain_chars = ct_size & 0xf;

    for (i = 0; i < LEA_BLOCK_LEN; i++)
        CTR[i] = IV[i];

    for (i = 0; i < num_Blocks; i++)
    {
        LEA_Encryption(Y, CTR, RK, LEA_Rounds);
        for (j = 0; j < LEA_BLOCK_LEN; j++)
        {
            pt[(i << 4) + j] = ct[(i << 4) + j] ^ Y[j];
        }

        for (n = 15; n >= 0; n--)
        {
            CTR[n]++;
            if (CTR[n])
                break;
        }
        

        // If CTR is out of range, treat as an error
        for (n = 0; n < 16; n++)
        {
            if (CTR[n] != 0)
            {
                flag = 0;
                break;
            }
        }
        if (flag)
            return;
    }

    if (remain_chars)
    {
        LEA_Encryption(Y, CTR, RK, LEA_Rounds);
        for (i = 0; i < remain_chars; i++)
        {
            pt[(num_Blocks << 4) + i] = ct[(num_Blocks << 4) + i] ^ Y[i];
        }
    }
}

