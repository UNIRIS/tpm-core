/*  Compile:
    gcc sk_gen.c -o sk_gen uniris-tpm.c -ltss2-esys -lcrypto

    Verify:
    sudo ./sk_gen
    xxd -p $file_name.bin | tr -d '\n'
*/

#include <stdio.h>
#include <openssl/sha.h>
#include "uniris-tpm.h"

void main()
{
    initializeTPM(10);

    INT publicKeySize = 0;
    BYTE *asnkey;

    BYTE hash256[32];
    INT signLen = 0;
    BYTE *eccSign;

    asnkey = getPublicKey(0, &publicKeySize);
    printf("\n Signing Root Public Key = \n");
    for (int v = 26; v < publicKeySize; v++)
    {
        printf("%02x", asnkey[v]);
    }

    asnkey = getPublicKey(10, &publicKeySize);
    printf("\n\n Uncompressed Public Key (to be signed) = \n");
    for (int v = 26; v < publicKeySize; v++)
    {
        printf("%02x", asnkey[v]);
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, asnkey + 26, publicKeySize - 26);
    SHA256_Final(hash256, &ctx);

    printf("\n\n Hash = ");
    for (int v = 0; v < SHA256_DIGEST_LENGTH; v++)
    {
        printf("%02x", hash256[v]);
    }

    eccSign = signECDSA(0, hash256, &signLen, false);
    printf("\n\n ECC Sign (ASN.1 DER) = \n");
    for (int v = 0; v < signLen; v++)
    {
        printf("%02x", eccSign[v]);
    }

    char file_name[32 * 2 + 4 + 1];
    for (int v = 0; v < SHA256_DIGEST_LENGTH; v++)
    {
        snprintf(file_name + (2 * v), 2 + 1, "%02x", hash256[v]);
    }
    snprintf(file_name + 64, 5, ".bin");
    printf("\n\n Filename = %s", file_name);

    FILE *write_ptr;
    write_ptr = fopen(file_name, "wb"); // w for write, b for binary
    fwrite(eccSign, signLen, 1, write_ptr);
    printf("\n\n Certificate creation successful\n\n");
}
