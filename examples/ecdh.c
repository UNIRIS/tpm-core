/* Creates two ECC keys (primary+euphemeral) and then derives the Point Z (shared secret) under ECDH
   Executes:
   Esys_Initialize()
   Esys_StartAuthSession()
   Esys_CreatePrimary()
   Esys_ECDH_KeyGen()
   Compile: gcc ecdh.c -ltss2-esys -o ecdh
*/

#include <tss2/tss2_esys.h>
#include <stdio.h>
#include <stdlib.h>

void main()
{
    TSS2_RC r;

    ESYS_CONTEXT *esys_context;
    r = Esys_Initialize(&esys_context, NULL, NULL);
    if (r != TSS2_RC_SUCCESS)
    {
        printf("\n ERROR: Esys-Initialize()");
    }

    TPM2B_SENSITIVE_CREATE inSensitive =
        {
            .size = 0,
            .sensitive = {
                .userAuth = {
                    .size = 0,
                    .buffer = {0},
                },
                .data = {.size = 0, .buffer = {0}}}};

    TPM2B_PUBLIC inPublicECC = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },

            .parameters.eccDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL,
                    .keyBits.aes = 256,
                    .mode.aes = TPM2_ALG_CFB,
                },
                .scheme = {.scheme = TPM2_ALG_ECDSA, .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}}},
                .curveID = TPM2_ECC_NIST_P256,
                .kdf = {
                    TPM2_ALG_NULL,
                    .details = {},
                },
            },
            .unique.ecc = {
                .x = {.size = 0, .buffer = {0}},
                .y = {
                    .size = 0,
                    .buffer = {},
                },

            },
        }

    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {}};

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}};

    ESYS_TR objectHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                              &session);
    if (r != TSS2_RC_SUCCESS)
    {
        printf("ERROR:"
               "Esys_StartAuthSession");
        exit(1);
    }

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, session,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublicECC,
                           &outsideInfo, &creationPCR, &objectHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\n Error: Receiver Primary Key Creation Failed");
    }

    printf("\n\n Public Key:\n X=");
    for (int i = 0; i < (*outPublic).publicArea.unique.ecc.x.size; i++)
    {
        printf("%02x", (*outPublic).publicArea.unique.ecc.x.buffer[i]);
    }

    printf("\nY=");
    for (int i = 0; i < (*outPublic).publicArea.unique.ecc.y.size; i++)
    {
        printf("%02x", (*outPublic).publicArea.unique.ecc.y.buffer[i]);
    }

    /****************************************Shared Secret Generation *******************************************/

    TPM2B_ECC_POINT *zPoint = NULL;
    TPM2B_ECC_POINT *pubPoint = NULL;

    r = Esys_ECDH_KeyGen(esys_context, objectHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &zPoint, &pubPoint);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\n\nError: keyGen()");
    }

    printf("\n\n Ephemeral Public Key");
    printf("\nX=");
    for (int i = 0; i < (*pubPoint).point.x.size; i++)
    {
        printf("%02x", (*pubPoint).point.x.buffer[i]);
    }
    printf("\nY=");
    for (int i = 0; i < (*pubPoint).point.y.size; i++)
    {
        printf("%02x", (*pubPoint).point.y.buffer[i]);
    }
    printf("\n\n The shared key: Z point=");
    printf("\nX=");
    for (int i = 0; i < (*zPoint).point.x.size; i++)
    {
        printf("%02x", (*zPoint).point.x.buffer[i]);
    }
    printf("\nY=");
    for (int i = 0; i < (*zPoint).point.y.size; i++)
    {
        printf("%02x", (*zPoint).point.y.buffer[i]);
    }
    printf("\n");
}
