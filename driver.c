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

    BYTE eph_pub[65] = {0x04, 0x1F, 0x51, 0xAE, 0x5D, 0x01, 0xB8, 0xAC, 0x0D, 0x3F, 0x12, 0xF1, 0xF6, 0x35, 0xCF, 0x70, 0xD9, 0x77, 0x2B, 0x47, 0x69, 0x15, 0xBC, 0xF5, 0x77, 0xE9, 0x3D, 0x82, 0xEE, 0x12, 0x53, 0x05, 0x62, 0x7C, 0x71, 0x0A, 0x7B, 0x78, 0x5B, 0x3D, 0x15, 0x56, 0x83, 0xB4, 0xF9, 0x92, 0x6F, 0x3E, 0xC2, 0x49, 0xA6, 0x1F, 0x53, 0x4B, 0x8E, 0x2F, 0xA5, 0x31, 0xDA, 0xC9, 0x70, 0x3A, 0x81, 0xB6, 0x82};
    BYTE *zPoint;
    for (int i = 1; i <= 4; i++)
    {

        asnkey = getPublicKey(i, &publicKeySize);
        printf("\n\nPrevious Key = \n");
        for (int v = 0; v < publicKeySize; v++)
        {
            printf("%02x", asnkey[v]);
        }
        
        
        printf("\n\nSign Key Index: %d", getKeyIndex());
        eccSign = signECDSA(i, hash256, &signLen, true);
        printf("\nECC Sign (ASN.1 DER) = \n");
        for (int v = 0; v < signLen; v++)
        {
            printf("%02x", eccSign[v]);
        }

        zPoint = getECDHPoint(i, eph_pub);
        printf("\n\nZ Point (Uncompressed/Raw) = \n");
        for (int v = 0; v < 65; v++)
        {
            printf("%02x", zPoint[v]);
        }

        printf("\nAfter Sign Key Index: %d", getKeyIndex());

        asnkey = getPublicKey(i + 1, &publicKeySize);
        printf("\n\nNext Key = \n");
        for (int v = 0; v < publicKeySize; v++)
        {
            printf("%02x", asnkey[v]);
        }
        printf("\n\n----------------------------------------------------------------------");
    }
    printf("\n\n");
}