/* Gets 20 bytes from TPM,
   finally prints it.
   Executes:
   Esys_Initialize()
   Esys_GetRandom()
   Compile: gcc random-gen.c -ltss2-esys -o random-gen
*/


#include <stdio.h>
#include <stdlib.h>
#include <tss2/tss2_esys.h>

int main() {

    TSS2_RC r;

    /* Initialize the ESAPI context */
    ESYS_CONTEXT *ctx;
    r = Esys_Initialize(&ctx, NULL, NULL);

    if (r != TSS2_RC_SUCCESS){
        printf("\nError: Esys_Initialize\n");
        exit(1);
    }

    /* Get random data */
    TPM2B_DIGEST *random_bytes;
    r = Esys_GetRandom(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 20,
                       &random_bytes);

    if (r != TSS2_RC_SUCCESS){
        printf("\nError: Esys_GetRandom\n");
        exit(1);
    }

    printf("\n");
    for (int i = 0; i < random_bytes->size; i++) {
        printf("0x%x ", random_bytes->buffer[i]);
    }
    printf("\n");
    exit(0);
}
