/* Creates a primary ECC key and signs a static hash of 20 BYTEs,
   finally verifies the signature.
   Executes:
   Esys_Initialize()
   Esys_StartAuthSession()
   Esys_ECC_Parameters()
   Esys_CreatePrimary()
   Esys_Sign()
   Esys_VerifySignature()
   Compile: gcc ecc-sign-verify.c -ltss2-esys -o ecc-sign-verify
*/

#include <stdio.h>
#include <tss2/tss2_esys.h>
#include <stdlib.h>
#include <string.h>

#define ASN1_SEQ 0x30
#define ASN1_INT 0x02
#define ASN1_OID 0x06
#define ASN1_BitString 0x03
#define PRIME_LEN 32

typedef unsigned char BYTE;
typedef unsigned short INT;

BYTE pubKeyASN[4 + 9 + 10 + 4 + PRIME_LEN + PRIME_LEN];
BYTE sigEccASN[2 + 2 + PRIME_LEN + 2 + PRIME_LEN + 2];

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

    //TPMA_OBJECT_RESTRICTED -- For hash created by TPM

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
            .parameters.eccDetail = {.symmetric = {
                                         .algorithm = TPM2_ALG_NULL,
                                         .keyBits.aes = 256,
                                         .mode.aes = TPM2_ALG_CFB,
                                     },
                                     .scheme = {.scheme = TPM2_ALG_ECDSA, .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}}},
                                     .curveID = TPM2_ECC_NIST_P256,
                                     .kdf = {.scheme = TPM2_ALG_NULL, .details = {}}},
            .unique.ecc = {.x = {.size = 0, .buffer = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60}}, .y = {.size = 0, .buffer = {}}},
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

    TPMI_ECC_CURVE curveID = TPM2_ECC_NIST_P256;
    TPMS_ALGORITHM_DETAIL_ECC *parameters;

    r = Esys_ECC_Parameters(
        esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        curveID,
        &parameters);

    printf("\nECC Parameters:\nP = ");
    for (int v = 0; v < (*parameters).p.size; v++)
    {
        printf("%02x ", (*parameters).p.buffer[v]);
    }
    printf("\nA = ");
    for (int v = 0; v < (*parameters).a.size; v++)
    {
        printf("%02x ", (*parameters).a.buffer[v]);
    }
    printf("\nB = ");
    for (int v = 0; v < (*parameters).b.size; v++)
    {
        printf("%02x ", (*parameters).b.buffer[v]);
    }
    printf("\nGx= ");
    for (int v = 0; v < (*parameters).gX.size; v++)
    {
        printf("%02x ", (*parameters).gX.buffer[v]);
    }
    printf("\nGy= ");
    for (int v = 0; v < (*parameters).gY.size; v++)
    {
        printf("%02x ", (*parameters).gY.buffer[v]);
    }
    printf("\nN = ");
    for (int v = 0; v < (*parameters).n.size; v++)
    {
        printf("%02x ", (*parameters).n.buffer[v]);
    }
    printf("\nH = ");
    for (int v = 0; v < (*parameters).h.size; v++)
    {
        printf("%02x ", (*parameters).h.buffer[v]);
    }

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, session,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublicECC,
                           &outsideInfo, &creationPCR, &objectHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\nError: Primary Key Creation Failed\n");
        exit(1);
    }
    /*
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
    */
    INT asnKeySize = 0;
    BYTE *asnkey = keyToASN(outPublic->publicArea.unique.ecc.x.buffer,
                            outPublic->publicArea.unique.ecc.x.size,
                            outPublic->publicArea.unique.ecc.y.buffer,
                            outPublic->publicArea.unique.ecc.y.size,
                            &asnKeySize);

    printf("\n\nPublic Key (ASN.1 DER) = \n");
    for (int v = 0; v < asnKeySize; v++)
    {
        printf("%02x", asnkey[v]);
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
    /*
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
    */
    INT asnSignSize = 0;
    BYTE *asnsign = signToASN(signature->signature.ecdsa.signatureR.buffer,
                              signature->signature.ecdsa.signatureR.size,
                              signature->signature.ecdsa.signatureS.buffer,
                              signature->signature.ecdsa.signatureS.size,
                              &asnSignSize);

    printf("\n\nECC Signature (ASN.1 DER) = \n");
    for (int v = 0; v < asnSignSize; v++)
    {
        printf("%02x", asnsign[v]);
    }
    printf("\n\n");

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

    exit(0);
}
