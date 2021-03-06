#include "uniris-tpm.h"

void initialize()
{
    rc = Esys_Initialize(&esys_context, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS)
    {
        printf("\nError: Esys Initialization Failed\n");
        exit(1);
    }
}

void setSession()
{
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};
    TPM2B_NONCE *nonce;
    rc = Esys_GetRandom(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 32,
                        &nonce);

    if (rc != TSS2_RC_SUCCESS)
    {
        printf("\nError: Get Random Bytes Failed\n");
        exit(1);
    }

    rc = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               nonce,
                               TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                               &session);

    if (rc != TSS2_RC_SUCCESS)
    {
        printf("\nError: Auth Session Failed\n");
        exit(1);
    }
    Esys_Free(nonce);
}

BYTE *keyToASN(BYTE *x, INT sizeX, BYTE *y, INT sizeY, INT *asnKeySize)
{
    BYTE asnHeader[] = {ASN1_SEQ, 0x59, ASN1_SEQ, 0x13};
    BYTE keyType[] = {ASN1_OID, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
    BYTE curveType[] = {ASN1_OID, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    BYTE pubKeyHeader[] = {ASN1_BitString, 0x42, 0x00, 0x04};

    int index = 0;
    memcpy(pubKeyASN + index, asnHeader, sizeof(asnHeader));
    index += sizeof(asnHeader);

    memcpy(pubKeyASN + index, keyType, sizeof(keyType));
    index += sizeof(keyType);

    memcpy(pubKeyASN + index, curveType, sizeof(curveType));
    index += sizeof(curveType);

    memcpy(pubKeyASN + index, pubKeyHeader, sizeof(pubKeyHeader));
    index += sizeof(pubKeyHeader);

    memcpy(pubKeyASN + index, x, sizeX);
    index += sizeX;

    memcpy(pubKeyASN + index, y, sizeY);
    index += sizeY;

    *asnKeySize = index;
    return pubKeyASN;
}





BYTE *getPublicKey(INT *publicKeySize)
{
    TPM2B_SENSITIVE_CREATE inSensitive = {
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
                                 TPMA_OBJECT_ADMINWITHPOLICY |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),

            .authPolicy = {
                .size = 32,
                .buffer = {0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
                           0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
                           0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA}},
            .parameters.eccDetail = {.symmetric = {
                                         .algorithm = TPM2_ALG_NULL,
                                         .keyBits.aes = 256,
                                         .mode.sym = TPM2_ALG_CFB,
                                     },
                                     .scheme = {.scheme = TPM2_ALG_ECDSA, .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}}},
                                     .curveID = TPM2_ECC_NIST_P256,
                                     .kdf = {.scheme = TPM2_ALG_NULL, .details = {}}},
            .unique.ecc = {.x = {.size = 32, .buffer = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, .y = {.size = 32, .buffer = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
        }};

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    ESYS_TR objectHandle = ESYS_TR_NONE;
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    rc = Esys_CreatePrimary(esys_context, ESYS_TR_RH_ENDORSEMENT, session,
                            ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublicECC,
                            &outsideInfo, &creationPCR, &objectHandle,
                            &outPublic, &creationData, &creationHash,
                            &creationTicket);

    if (rc != TSS2_RC_SUCCESS)
    {
        printf("\nError: Primary Key Creation Failed\n");
        exit(1);
    }

    INT asnKeySize = 0;
    BYTE *asnkey = keyToASN(outPublic->publicArea.unique.ecc.x.buffer,
                            outPublic->publicArea.unique.ecc.x.size,
                            outPublic->publicArea.unique.ecc.y.buffer,
                            outPublic->publicArea.unique.ecc.y.size,
                            &asnKeySize);

    memcpy(publicKeySize,&asnKeySize, sizeof(asnKeySize));
    return asnkey;
}
