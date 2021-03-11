#include "uniris-tpm.h"

void initialize()
{
    rc = Esys_Initialize(&esys_context, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS)
    {
        printf("\nError: Esys Initialization Failed\n");
        exit(1);
    }
    isRootKey = false;
    BYTE *key = getPublicKey(0, &rootKeySize);
    memset(rootKeyASN, 0, 4 + 9 + 10 + 4 + PRIME_LEN + PRIME_LEN);
    memset(rootKeyHash, 0, 32);
    memcpy(rootKeyASN, key, rootKeySize);

    previousKeyHandle = ESYS_TR_NONE;
    nextKeyHandle = ESYS_TR_NONE;
    previousKeyIndex = -1;
    nextKeyIndex = previousKeyIndex + 1;

    currentKeyHandle = ESYS_TR_NONE;
}

BYTE *keyToASN(BYTE *x, INT sizeX, BYTE *y, INT sizeY, INT *asnKeySize)
{
    BYTE *pubKeyASN = malloc(4 + 9 + 10 + 4 + PRIME_LEN + PRIME_LEN);
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

BYTE *signToASN(BYTE *r, INT sizeR, BYTE *s, INT sizeS, INT *asnSignSize)
{

    int index = 0;
    sigEccASN[index++] = ASN1_SEQ;

    int asnLen = (PRIME_LEN * 2) + 4;
    if (r[0] > 127) // check MSB, R needs padding to remain positive
        asnLen++;
    if (s[0] > 127) // check MSB, S needs padding to remain positive
        asnLen++;
    /*
	if(asnLen > 127)
		sigEccASN[index++] = 0x81;
    */
    sigEccASN[index++] = asnLen;

    // R value
    sigEccASN[index++] = ASN1_INT;
    if (r[0] > 127)
    {
        sigEccASN[index++] = PRIME_LEN + 1;
        sigEccASN[index++] = 0x00; // Extra byte to ensure R remains positive
    }
    else
        sigEccASN[index++] = PRIME_LEN;
    memcpy(sigEccASN + index, r, PRIME_LEN);
    index += PRIME_LEN;

    // S value
    sigEccASN[index++] = ASN1_INT;
    if (s[0] > 127)
    {
        sigEccASN[index++] = PRIME_LEN + 1;
        sigEccASN[index++] = 0x00; // Extra byte to ensure S remains positive
    }
    else
        sigEccASN[index++] = PRIME_LEN;
    memcpy(sigEccASN + index, s, PRIME_LEN);
    index += PRIME_LEN;

    *asnSignSize = index;

    return sigEccASN;
}

BYTE *getPublicKey(INT index, INT *publicKeySize)
{
    if (index == 0 && isRootKey == true)
    {
        memcpy(publicKeySize, &rootKeySize, sizeof(rootKeySize));
        return rootKeyASN;
    }
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
            .unique.ecc = {.x = {.size = 32, .buffer = {0}}, .y = {.size = 32, .buffer = {0}}},

        }};

    memcpy(inPublicECC.publicArea.unique.ecc.x.buffer, rootKeyHash, 32);
    memcpy(inPublicECC.publicArea.unique.ecc.y.buffer, &index, sizeof(index));

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;
    TPM2B_PUBLIC *eccPublicKey = NULL;

    rc = Esys_CreatePrimary(esys_context, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD,
                            ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublicECC,
                            &outsideInfo, &creationPCR, &currentKeyHandle,
                            &eccPublicKey, &creationData, &creationHash,
                            &creationTicket);
    if (rc != TSS2_RC_SUCCESS)
    {
        printf("\nError: Primary Key Creation Failed\n");
        exit(1);
    }
    if (index == 0)
    {
        rootKeyHandle = currentKeyHandle;
        isRootKey = true;
        TPM2B_MAX_BUFFER data = {.size = 64, .buffer = {}};
        memcpy(data.buffer, (*eccPublicKey).publicArea.unique.ecc.x.buffer, 32);
        memcpy(data.buffer + 32, (*eccPublicKey).publicArea.unique.ecc.y.buffer, 32);
        TPMT_TK_HASHCHECK *hashTicket = NULL;
        Esys_Hash(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &data, TPM2_ALG_SHA256, ESYS_TR_RH_OWNER, &creationHash, &hashTicket);
        memcpy(rootKeyHash, creationHash, 32);
    }

    INT keySize = 0;
    BYTE *key = keyToASN(eccPublicKey->publicArea.unique.ecc.x.buffer,
                         eccPublicKey->publicArea.unique.ecc.x.size,
                         eccPublicKey->publicArea.unique.ecc.y.buffer,
                         eccPublicKey->publicArea.unique.ecc.y.size, &keySize);

    memcpy(publicKeySize, &keySize, sizeof(keySize));
    return key;
}

BYTE *signECDSA(INT index, BYTE *hashToSign, INT *eccSignSize)
{

    TPM2B_DIGEST hashTPM = {.size = 32};
    memcpy(hashTPM.buffer, hashToSign, 32);

    TPMT_SIG_SCHEME inScheme = {.scheme = TPM2_ALG_NULL};

    TPMT_TK_HASHCHECK hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_ENDORSEMENT,
        .digest = {0}};

    TPMT_SIGNATURE *signature = NULL;

    ESYS_TR signingKeyHandle = ESYS_TR_NONE;

    if (index == 0)
    {
        signingKeyHandle = rootKeyHandle;
    }
    INT size = 0;
    if (index != previousKeyIndex)
    {
        getPublicKey(index, &size);
        previousKeyIndex = index;
        previousKeyHandle = currentKeyHandle;

        getPublicKey(index + 1, &size);
        nextKeyIndex = index + 1;
        nextKeyHandle = currentKeyHandle;
    }
    signingKeyHandle = previousKeyHandle;
    rc = Esys_Sign(esys_context, signingKeyHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &hashTPM, &inScheme, &hash_validation, &signature);

    updateHandlesIndexes();

    INT asnSignSize = 0;
    BYTE *asnsign = signToASN(signature->signature.ecdsa.signatureR.buffer,
                              signature->signature.ecdsa.signatureR.size,
                              signature->signature.ecdsa.signatureS.buffer,
                              signature->signature.ecdsa.signatureS.size,
                              &asnSignSize);
    memcpy(eccSignSize, &asnSignSize, sizeof(asnSignSize));
    return asnsign;
}

void updateHandlesIndexes()
{
    INT size = 0;
    Esys_FlushContext(esys_context, previousKeyHandle);
    previousKeyHandle = nextKeyHandle;
    previousKeyIndex = nextKeyIndex;

    nextKeyIndex = previousKeyIndex + 1;
    getPublicKey(nextKeyIndex, &size);
    nextKeyHandle = currentKeyHandle;
}