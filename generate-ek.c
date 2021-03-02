/* Creates a primary ECC key and signs a static hash of 20 BYTEs,
   finally verifies the signature.
   Executes:
   Esys_Initialize()
   Esys_StartAuthSession()
   Esys_ECC_Parameters()
   Esys_CreatePrimary()
   Esys_Sign()
   Esys_VerifySignature()
   Compile: gcc ecc-sign-verify.c -ltss2-esys -o ecc-sign-verify.o
*/

#include <stdio.h>
#include <tss2/tss2_esys.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char BYTE;
typedef unsigned short INT;

int main()
{
    TSS2_RC r;

    /* Initialize the ESAPI context */
    ESYS_CONTEXT *esys_context;
    r = Esys_Initialize(&esys_context, NULL, NULL);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\nError: Esys Initialization Failed\n");
        exit(1);
    }
    
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                .size = 0,
                .buffer = {0},
            },
            .data = {.size = 0, .buffer = {0}}}};
    //TPMA_OBJECT_USERWITHAUTH
    TPM2B_PUBLIC inPublicECC = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_ADMINWITHPOLICY
                                | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM
                                | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 32,
                .buffer = { 0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
                            0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
                            0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA}
                //.buffer = {0xCA,  0x3D,  0x0A,  0x99,  0xA2,  0xB9, 0x39,  0x06,  0xF7,  0xA3,  0x34,  0x24, 0x14,  0xEF,  0xCF,  0xB3,  0xA3,  0x85, 0xD4,  0x4C,  0xD1,  0xFD,  0x45,  0x90, 0x89,  0xD1, 0x9B,  0x50,  0x71,  0xC0, 0xB7, 0xA0}
            
            },
            .parameters.eccDetail = {.symmetric = {
                                         .algorithm = TPM2_ALG_AES,
                                         .keyBits.aes = 128,
                                         .mode.sym = TPM2_ALG_CFB,
                                     },
                                     .scheme = {.scheme = TPM2_ALG_NULL, .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}}},
                                     .curveID = TPM2_ECC_NIST_P256,
                                     .kdf = {.scheme = TPM2_ALG_NULL, .details = {}}},
            .unique.ecc = { .x = {.size = 32, .buffer = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                            .y = {.size = 32, .buffer = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}},
        }};

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

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
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                              &session);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\nError: Auth Session Failed\n");
        exit(1);
    }

    r = Esys_CreatePrimary(esys_context, TPM2_RH_ENDORSEMENT, session,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublicECC,
                           &outsideInfo, &creationPCR, &objectHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\nError: Primary Key Creation Failed\n");
        exit(1);
    }

    printf("\n\nPublic Key:\nX = ");
    for (int v = 0; v < (*outPublic).publicArea.unique.ecc.x.size; v++)
    {
        printf("%02x ", (*outPublic).publicArea.unique.ecc.x.buffer[v]);
    }
    printf("\nY = ");
    for (int v = 0; v < (*outPublic).publicArea.unique.ecc.y.size; v++)
    {
        printf("%02x ", (*outPublic).publicArea.unique.ecc.y.buffer[v]);
    }

    TPM2B_NAME *nameKeySign = NULL;
    TPM2B_NAME *keyQualifiedName = NULL;

    /*
    r = Esys_ReadPublic(esys_context,
                        objectHandle,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &outPublic,
                        &nameKeySign,
                        &keyQualifiedName);

   */
/*
    TPM2B_DIGEST pcr_digest_zero = {
        .size = 32,
        //SHA256(UNIRIS)
        .buffer = {0x54, 0xc1, 0xa8, 0x30, 0xfa, 0xfd, 0x24, 0xd5,
                   0xe8, 0xec, 0xe4, 0x32, 0xbd, 0x6e, 0x67, 0xd8,
                   0xa0, 0xe6, 0x93, 0x05, 0x3b, 0x9f, 0x0d, 0x3b,
                   0xed, 0x16, 0xc9, 0x10, 0xb6, 0x2c, 0xb8, 0xe9}};

    TPMT_SIG_SCHEME inScheme = {.scheme = TPM2_ALG_NULL};
    TPMT_TK_HASHCHECK hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_OWNER,
        .digest = {0}};

    TPMT_SIGNATURE *signature = NULL;

    r = Esys_Sign(
        esys_context,
        objectHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pcr_digest_zero,
        &inScheme,
        &hash_validation,
        &signature);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\nError: ECC Signing Failed\n");
        exit(1);
    }

    printf("\n\nSignature:\nR = ");
    for (int i = 0; i < (*signature).signature.ecdsa.signatureR.size; i++)
    {
        printf("%02x ", (*signature).signature.ecdsa.signatureR.buffer[i]);
    }
    printf("\nS = ");
    for (int i = 0; i < (*signature).signature.ecdsa.signatureS.size; i++)
    {
        printf("%02x ", (*signature).signature.ecdsa.signatureS.buffer[i]);
    }

    TPMT_TK_VERIFIED *validation = NULL;

    r = Esys_VerifySignature(
        esys_context,
        objectHandle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pcr_digest_zero,
        signature,
        &validation);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\nError: ECC Signature Verfication Failed\n");
        exit(1);
    }
*/
    exit(0);
}
