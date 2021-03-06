#include "uniris-tpm.h"

void main(){
    initialize();
    setSession();

    INT publicKeySize = 0;
    BYTE *asnkey = getPublicKey(&publicKeySize);
    
    printf("\n\nPublic Key (ASN.1 DER) = \n");
    for (int v = 0; v < publicKeySize; v++)
    {
        printf("%02x", asnkey[v]);
    }
}