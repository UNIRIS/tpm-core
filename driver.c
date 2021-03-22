#include <stdio.h>
#include <time.h>
#include "uniris-tpm.h"

void main()
{
    initializeTPM(1);

    INT publicKeySize = 0;
    clock_t t;
    BYTE *asnkey;
    double time_taken;

    BYTE hash256[32] = {0x54, 0xc1, 0xa8, 0x30, 0xfa, 0xfd, 0x24, 0xd5, 0xe8, 0xec, 0xe4, 0x32, 0xbd, 0x6e, 0x67, 0xd8, 0xa0, 0xe6, 0x93, 0x05, 0x3b, 0x9f, 0x0d, 0x3b, 0xed, 0x16, 0xc9, 0x10, 0xb6, 0x2c, 0xb8, 0xe9};
    INT signLen = 0;
    BYTE *eccSign;

    //t = clock();
    //t = clock() - t;
    //time_taken = ((double)t) / CLOCKS_PER_SEC; // in seconds
    //printf("\ngetPublicKey() took %f seconds to execute \n", time_taken);

    for (int i = 1; i <= 4; i++)
    {

        asnkey = getPublicKey(i, &publicKeySize);
        printf("\n\nPrevious Key = \n");
        for (int v = 0; v < publicKeySize; v++)
        {
            printf("%02x", asnkey[v]);
        }
        printf("\n\nSign Key Index: %d", getKeyIndex());
        eccSign = signECDSA(i, hash256, &signLen);
        printf("\nECC Sign (ASN.1 DER) = \n");
        for (int v = 0; v < signLen; v++)
        {
            printf("%02x", eccSign[v]);
        }
        printf("\nAfter Sign Key Index: %d", getKeyIndex());

        asnkey = getPublicKey(i + 1, &publicKeySize);
        printf("\n\nNext Key = \n");
        for (int v = 0; v < publicKeySize; v++)
        {
            printf("%02x", asnkey[v]);
        }
        printf("\n----------------------------------------------------------------------");
    }
    printf("\n");
}