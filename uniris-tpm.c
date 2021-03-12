#include "uniris-tpm.h"

void initializeTPM(INT index)
{
    rc = Esys_Initialize(&esys_context, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS)
    {
        printf("\nError: Esys Initialization Failed\n");
        exit(1);
    }

    previousKeyHandle = ESYS_TR_NONE;
    nextKeyHandle = ESYS_TR_NONE;
    setRootKey();
    setKeyIndex(index);
}

void keyToASN()
{
    BYTE asnHeader[] = {ASN1_SEQ, 0x59, ASN1_SEQ, 0x13};
    BYTE keyType[] = {ASN1_OID, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
    BYTE curveType[] = {ASN1_OID, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    BYTE pubKeyHeader[] = {ASN1_BitString, 0x42, 0x00, 0x04};

    int index = 0, size_x_y = 0;
    memcpy(currentKeyASN + index, asnHeader, sizeof(asnHeader));
    index += sizeof(asnHeader);

    memcpy(currentKeyASN + index, keyType, sizeof(keyType));
    index += sizeof(keyType);

    memcpy(currentKeyASN + index, curveType, sizeof(curveType));
    index += sizeof(curveType);

    memcpy(currentKeyASN + index, pubKeyHeader, sizeof(pubKeyHeader));
    index += sizeof(pubKeyHeader);

    size_x_y = currentKeyTPM->publicArea.unique.ecc.x.size;
    memcpy(currentKeyASN + index, currentKeyTPM->publicArea.unique.ecc.x.buffer, size_x_y);
    index += size_x_y;

    size_x_y = currentKeyTPM->publicArea.unique.ecc.y.size;
    memcpy(currentKeyASN + index, currentKeyTPM->publicArea.unique.ecc.y.buffer, size_x_y);
    index += size_x_y;

    currentKeySizeASN = index;
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

    else if (index != previousKeyIndex)
    {
        setKeyIndex(index);
        signingKeyHandle = previousKeyHandle;
    }

    else
        signingKeyHandle = previousKeyHandle;

    rc = Esys_Sign(esys_context, signingKeyHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &hashTPM, &inScheme, &hash_validation, &signature);
    if (index)
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
    Esys_FlushContext(esys_context, previousKeyHandle);
    previousKeyHandle = nextKeyHandle;
    previousKeyIndex = nextKeyIndex;
    memset(previousKeyASN, 0, ANS1_MAX_KEY_SIZE);
    memcpy(previousKeyASN, nextKeyASN, nextKeySizeASN);
    previousKeySizeASN = nextKeySizeASN;

    nextKeyIndex = previousKeyIndex + 1;
    generatePublicKey(nextKeyIndex);
    nextKeyHandle = currentKeyHandle;
    memset(nextKeyASN, 0, ANS1_MAX_KEY_SIZE);
    memcpy(nextKeyASN, currentKeyASN, currentKeySizeASN);
    nextKeySizeASN = currentKeySizeASN;
}

BYTE *getPublicKey(INT index, INT *publicKeySize)
{
    if (index == nextKeyIndex)
    {
        memcpy(publicKeySize, &nextKeySizeASN, sizeof(nextKeySizeASN));
        return nextKeyASN;
    }

    else if (index == previousKeyIndex)
    {
        memcpy(publicKeySize, &previousKeySizeASN, sizeof(previousKeySizeASN));
        return previousKeyASN;
    }

    else if (index == 0)
    {
        memcpy(publicKeySize, &rootKeySizeASN, sizeof(rootKeySizeASN));
        return rootKeyASN;
    }

    else
    {
        Esys_FlushContext(esys_context, rootKeyHandle);
        generatePublicKey(index);
        Esys_FlushContext(esys_context, currentKeyHandle);

        BYTE *tempKey = malloc(ANS1_MAX_KEY_SIZE);
        memcpy(tempKey, currentKeyASN, currentKeySizeASN);
        memcpy(publicKeySize, &currentKeySizeASN, sizeof(currentKeySizeASN));

        setRootKey();
        return tempKey;
    }
}

void generatePublicKey(INT index)
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

    rc = Esys_CreatePrimary(esys_context, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD,
                            ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublicECC,
                            &outsideInfo, &creationPCR, &currentKeyHandle,
                            &currentKeyTPM, &creationData, &creationHash,
                            &creationTicket);
    if (rc != TSS2_RC_SUCCESS)
    {
        printf("\nError: Primary Key Creation Failed\n");
        exit(1);
    }

    keyToASN();
}

void setRootKey()
{
    memset(rootKeyASN, 0, ANS1_MAX_KEY_SIZE);
    memset(rootKeyHash, 0, PRIME_LEN);
    generatePublicKey(0);

    rootKeySizeASN = currentKeySizeASN;
    memcpy(rootKeyASN, currentKeyASN, currentKeySizeASN);
    rootKeyHandle = currentKeyHandle;

    TPM2B_MAX_BUFFER data = {.size = 64, .buffer = {}};
    memcpy(data.buffer, (*currentKeyTPM).publicArea.unique.ecc.x.buffer, 32);
    memcpy(data.buffer + 32, (*currentKeyTPM).publicArea.unique.ecc.y.buffer, 32);

    TPMT_TK_HASHCHECK *hashTicket = NULL;
    TPM2B_DIGEST *creationHash = NULL;

    Esys_Hash(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &data, TPM2_ALG_SHA256, ESYS_TR_RH_OWNER, &creationHash, &hashTicket);
    memcpy(rootKeyHash, creationHash, 32);
}

void setKeyIndex(INT index)
{
    if (index < 1)
        index = 1;
    previousKeyIndex = index;
    if (previousKeyHandle != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, previousKeyHandle);
    generatePublicKey(previousKeyIndex);
    previousKeyHandle = currentKeyHandle;
    previousKeySizeASN = currentKeySizeASN;

    memset(previousKeyASN, 0, ANS1_MAX_KEY_SIZE);
    memcpy(previousKeyASN, currentKeyASN, currentKeySizeASN);

    nextKeyIndex = previousKeyIndex + 1;
    if (nextKeyHandle != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, nextKeyHandle);
    generatePublicKey(nextKeyIndex);
    nextKeyHandle = currentKeyHandle;
    nextKeySizeASN = currentKeySizeASN;

    memset(nextKeyASN, 0, ANS1_MAX_KEY_SIZE);
    memcpy(nextKeyASN, currentKeyASN, currentKeySizeASN);

    currentKeyHandle = ESYS_TR_NONE;
}

INT getKeyIndex()
{
    return previousKeyIndex;
}