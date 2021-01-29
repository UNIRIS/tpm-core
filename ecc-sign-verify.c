/* Creates a primary ECC key and signs a static hash of 20 bytes,
   finally verifies the signature.
   Executes:
   Esys_Initialize()
   Esys_StartAuthSession()
   Esys_CreatePrimary()
   Esys_ReadPublic()
   Esys_Sign()
   Esys_VerifySignature()
   Compile: gcc ecc-sign-verify.c -ltss2-esys -o ecc-sign-verify.o
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

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0}
                 ,
             },
            .data = {
                 .size = 0,
                 .buffer = {0}
             }
        }
    };

//TPMA_OBJECT_RESTRICTED |

    TPM2B_PUBLIC inPublicECC = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA1,
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
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB,
                 },
                 .scheme = {
                      .scheme = TPM2_ALG_ECDSA,
                      .details = {.ecdsa =
                                  {.hashAlg = TPM2_ALG_SHA1}
                      }
                  },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {.scheme =
                         TPM2_ALG_NULL,.details = {}
                  }
             },
            .unique.ecc = {
                 .x = {.size = 0,.buffer = {}},
                 .y = {.size = 0,.buffer = {}}
             }
            ,
        }
    };


    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {}
        ,
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };


    ESYS_TR objectHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetric = { .algorithm = TPM2_ALG_NULL };

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);

    if (r != TSS2_RC_SUCCESS){
        printf("\nError");
        exit(1);
        }

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, session,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublicECC,
                           &outsideInfo, &creationPCR, &objectHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);


    if (r != TSS2_RC_SUCCESS){
        printf("\nError");
        exit(1);

    TPM2B_NAME *nameKeySign = NULL;
    TPM2B_NAME *keyQualifiedName = NULL;


    r = Esys_ReadPublic(esys_context,
                        objectHandle,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &outPublic,
                        &nameKeySign,
                        &keyQualifiedName);

    if (r != TSS2_RC_SUCCESS){
        printf("\nError");
        exit(1);
        }

    TPM2B_DIGEST pcr_digest_zero = {
        .size = 20,
        .buffer = { 0x67, 0x68, 0x03, 0x3e, 0x21, 0x64, 0x68, 0x24, 0x7b, 0xd0,
                    0x31, 0xa0, 0xa2, 0xd9, 0x87, 0x6d, 0x79, 0x81, 0x8f, 0x8f }
    };



    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
    TPMT_TK_HASHCHECK hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_OWNER,
        .digest = {0}
    };

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

    if (r != TSS2_RC_SUCCESS){
        printf("\nError");
        exit(1);
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


    if (r != TSS2_RC_SUCCESS){
        printf("\nError");
        exit(1);
        }


/*
    TPM2B_ECC_POINT *zPoint = NULL;
    TPM2B_ECC_POINT *pubPoint = NULL;

    r = Esys_ECDH_KeyGen(
        esys_context,
        objectHandle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &zPoint,
        &pubPoint);

    if (r != TSS2_RC_SUCCESS){
        printf("\nError");
        exit(1);
        }

*/

exit(0);
}
