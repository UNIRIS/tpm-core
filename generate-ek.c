/* Creates a primary ECC key with default EK template
   and returns the URL-safe base64-encoded SHA256-hash of the EK Public Key 
   Executes:
   Esys_Initialize()
   Esys_StartAuthSession()
   Esys_CreatePrimary()
   Esys_Hash()
   Compile: gcc generate-ek.c -ltss2-esys -o generate-ek
*/

#include <stdio.h>
#include <tss2/tss2_esys.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char BYTE;
typedef long unsigned int INT;

static const unsigned char base64_table[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
//"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

BYTE *base64url_encode(BYTE *src, INT len, INT *out_len)
{
    BYTE *out, *pos, *end, *in;
    INT olen;

    olen = len * 4 / 3 + (2 + 2 * 3); /* 3-byte blocks to 4-byte */
    olen++;                           /* nul termination */
    if (olen < len)
        return NULL; /* integer overflow */
    out = malloc(olen);
    if (out == NULL)
        return NULL;

    end = src + len;
    in = src;
    pos = out;
    while (end - in >= 3)
    {
        *pos++ = base64_table[in[0] >> 2];
        *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_table[in[2] & 0x3f];
        in += 3;
    }

    if (end - in)
    {
        *pos++ = base64_table[in[0] >> 2];
        if (end - in == 1)
        {
            *pos++ = base64_table[(in[0] & 0x03) << 4];
            *pos++ = '%';
            *pos++ = '3';
            *pos++ = 'D';
        }
        else
        {
            *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = base64_table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '%';
        *pos++ = '3';
        *pos++ = 'D';
    }
    *pos = '\0';
    *out_len = pos - out;
    return out;
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

    TPM2B_PUBLIC inPublicECC = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,

            .objectAttributes = (TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_ADMINWITHPOLICY |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),

            .authPolicy = {
                .size = 32,
                .buffer = {0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
                           0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
                           0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA}},
            .parameters.eccDetail = {.symmetric = {
                                         .algorithm = TPM2_ALG_AES,
                                         .keyBits.aes = 128,
                                         .mode.sym = TPM2_ALG_CFB,
                                     },
                                     .scheme = {.scheme = TPM2_ALG_NULL, .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}}},
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
    TPMT_TK_HASHCHECK *hashTicket = NULL;

    TPM2B_NONCE nonce = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}};

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonce,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                              &session);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\nError: Auth Session Failed\n");
        exit(1);
    }

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_ENDORSEMENT, session,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublicECC,
                           &outsideInfo, &creationPCR, &objectHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\nError: Primary Key Creation Failed\n");
        exit(1);
    }

    TPM2B_MAX_BUFFER data = {.size = 64, .buffer = {}};
    memcpy(data.buffer, (*outPublic).publicArea.unique.ecc.x.buffer, 32);
    memcpy(data.buffer + 32, (*outPublic).publicArea.unique.ecc.y.buffer, 32);

    //Esys_TR_GetName
    r = Esys_Hash(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &data, TPM2_ALG_SHA256, ESYS_TR_RH_OWNER, &creationHash, &hashTicket);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\nError: Hash Calculation Failed\n");
        exit(1);
    }

    printf("\nEK Public Key Hash (SHA256):\n# = ");
    for (int v = 0; v < creationHash->size; v++)
    {
        printf("%02x", creationHash->buffer[v]);
    }

    INT keylen = 0;
    BYTE *base64key = base64url_encode(creationHash->buffer, creationHash->size, &keylen);

    printf("\n\nEK Public Key Hash (base64 URL-Safe):\n# = %s", base64key);

    printf("\n\nEK Public Key (raw):");
    printf("\nX = ");
    for (int v = 0; v < (*outPublic).publicArea.unique.ecc.x.size; v++)
    {
        printf("%02x ", (*outPublic).publicArea.unique.ecc.x.buffer[v]);
    }
    printf("\nY = ");
    for (int v = 0; v < (*outPublic).publicArea.unique.ecc.y.size; v++)
    {
        printf("%02x ", (*outPublic).publicArea.unique.ecc.y.buffer[v]);
    }

    printf("\n\nLink for EK Certificate (Intel Nuc):\nhttps://ekop.intel.com/ekcertservice/%s\n\n", base64key);
    exit(0);
}
