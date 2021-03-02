/* Creates a session, defines a NV space and writes 20 bytes to NVM of TPM,
   reads the data from NVM and finally undefines the NV space.
   Executes:
   Esys_Initialize()
   Esys_StartAuthSession()
   Esys_NV_DefineSpace()
   Esys_NV_Write()
   Esys_NV_Read()
   Esys_NV_UndefineSpace()
   Compile: gcc nvm-write-read.c -ltss2-esys -o nvm-write-read
*/

#include <stdio.h>
#include <tss2/tss2_esys.h>
#include <stdlib.h>

int main() {
    TSS2_RC r;

    /* Initialize the ESAPI context */
    ESYS_CONTEXT *esys_context;
    r = Esys_Initialize(&esys_context, NULL, NULL);

    if (r != TSS2_RC_SUCCESS){
        printf("\nError: Esys_Initialize\n");
        exit(1);
    }

    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
                              .keyBits = {.aes = 256},
                              .mode = {.aes = TPM2_ALG_CFB}
    };
    
    //TPMA_SESSION sessionAttributes;
    //memset(&sessionAttributes, 0, sizeof sessionAttributes);
    
    TPM2B_NONCE nonce = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonce,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                              &session);

    if (r != TSS2_RC_SUCCESS){
        printf("\nError\n");
        exit(1);
        }

    ESYS_TR nvHandle = ESYS_TR_NONE;
    TPM2B_AUTH auth = {.size = 20,
                       .buffer={10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                20, 21, 22, 23, 24, 25, 26, 27, 28, 29}};

    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex =TPM2_NV_INDEX_FIRST,
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = (
                TPMA_NV_OWNERWRITE |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_WRITE_STCLEAR |
                TPMA_NV_READ_STCLEAR |
                TPMA_NV_AUTHREAD |
                TPMA_NV_OWNERREAD
                ),
            .authPolicy = {
                 .size = 0,
                 .buffer = {},
             },
            .dataSize = 32,
        }
    };

    r = Esys_NV_DefineSpace(esys_context,
                            ESYS_TR_RH_OWNER,
                            session,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            &auth,
                            &publicInfo,
                            &nvHandle);

    if (r != TSS2_RC_SUCCESS){
        printf("\nError\n");
        exit(1);
        }

    UINT16 offset = 0;
    TPM2B_MAX_NV_BUFFER nv_write_data = { .size = 20,
                                         .buffer={0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                  1, 2, 3, 4, 5, 6, 7, 8, 9}};

    r = Esys_NV_Write(esys_context,
                      nvHandle,
                      nvHandle,
                      session,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      &nv_write_data,
                      offset);

    if (r != TSS2_RC_SUCCESS){
        printf("\nError\n");
        exit(1);
        }

    TPM2B_MAX_NV_BUFFER *nv_read_data = NULL;

    r = Esys_NV_Read(esys_context,
                     nvHandle,
                     nvHandle,
                     session,
                     ESYS_TR_NONE,
                     ESYS_TR_NONE,
                     20,
                     0,
                     &nv_read_data);

    printf("\nDATA FROM NVM:\n");

    for(int i=0; i<(*nv_read_data).size; i++){
        printf("0x%x ",(*nv_read_data).buffer[i]);
    }

    if (r != TSS2_RC_SUCCESS){
        printf("\nError\n");
        exit(1);
        }

    r = Esys_NV_UndefineSpace(esys_context,
                              ESYS_TR_RH_OWNER,
                              nvHandle,
                              session,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE);

    if (r != TSS2_RC_SUCCESS){
        printf("\nNV_UndefineSpace Error, trying again\n");
        r = Esys_NV_UndefineSpace(esys_context,
                                  ESYS_TR_RH_OWNER,
                                  nvHandle,
                                  session,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE);
        }

    if (r != TSS2_RC_SUCCESS){
        printf("\nError\n");
        exit(1);
        }

printf("\nSUCCESS\n");
exit(0);
}
