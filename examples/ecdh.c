/*******************************************************************************
 *   Archethic TPM Library
 *   (c) 2021 Varun Deshpande, Lucy Sharma, Uniris
 *
 *  Licensed under the GNU Affero General Public License, Version 3 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.gnu.org/licenses/agpl-3.0.en.html
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

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
#include <string.h>

typedef unsigned char INT;
#define ASN1_SEQ 0x30
#define ASN1_INT 0x02
#define ASN1_OID 0x06
#define ASN1_BitString 0x03
#define PRIME_LEN 32

BYTE sigEccASN[2 + 2 + PRIME_LEN + 2 + PRIME_LEN + 2];

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
                                 TPMA_OBJECT_ADMINWITHPOLICY |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
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
                                         .algorithm = TPM2_ALG_NULL,
                                         .keyBits.aes = 256,
                                         .mode.sym = TPM2_ALG_CFB,
                                     },
                                     .scheme = {.scheme = TPM2_ALG_NULL, .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}}},
                                     .curveID = TPM2_ECC_NIST_P256,
                                     .kdf = {.scheme = TPM2_ALG_NULL, .details = {}}},
            .unique.ecc = {.x = {.size = 32, .buffer = {0}}, .y = {.size = 32, .buffer = {0}}},

        }};
    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {}};

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}};

    ESYS_TR eccHandle = ESYS_TR_NONE;
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

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublicECC,
                           &outsideInfo, &creationPCR, &eccHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\n Error: Receiver Primary Key Creation Failed");
    }

    printf("\n\nPublic Key:\nX=");
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

    TPM2B_ECC_POINT inPoint = {
        .size = 0,
        .point = {
            .x = {
                .size = 32,
                .buffer = {
                    0xa0, 0x06, 0x85, 0xba, 0xdb, 0x57, 0x3d, 0x83, 0x63, 0x00, 0xc9, 0x32, 0xf0, 0x91, 0xf4, 0x0d, 0x36, 0x47, 0xcd, 0x8c, 0xba, 0x6d, 0x76, 0x66, 0x56, 0x04, 0x82, 0x58, 0xec, 0x55, 0xd6, 0xeb},
            },
            .y = {.size = 32, .buffer = {0xe4, 0x61, 0xf4, 0x54, 0xae, 0xe3, 0x7c, 0x7f, 0xb3, 0xdb, 0x09, 0xfa, 0x3b, 0x9e, 0x66, 0xde, 0x30, 0x87, 0x45, 0x40, 0x5b, 0x5f, 0x59, 0xb8, 0x0e, 0x3d, 0xbb, 0x61, 0xf3, 0xd3, 0xc3, 0x69}}}};

    r = Esys_ECDH_ZGen(
        esys_context,
        eccHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inPoint,
        &zPoint);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\n\nError: keyGen()");
    }

    TPM2B_DIGEST pcr_digest_zero = {
        .size = 32,
        // SHA256(UNIRIS)
        .buffer = {0x54, 0xc1, 0xa8, 0x30, 0xfa, 0xfd, 0x24, 0xd5,
                   0xe8, 0xec, 0xe4, 0x32, 0xbd, 0x6e, 0x67, 0xd8,
                   0xa0, 0xe6, 0x93, 0x05, 0x3b, 0x9f, 0x0d, 0x3b,
                   0xed, 0x16, 0xc9, 0x10, 0xb6, 0x2c, 0xb8, 0xe9}};

    TPMT_SIG_SCHEME inScheme = {.scheme = TPM2_ALG_ECDSA, .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}}};
    TPMT_TK_HASHCHECK hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_OWNER,
        .digest = {0}};

    TPMT_SIGNATURE *signature = NULL;

    r = Esys_Sign(
        esys_context,
        eccHandle,
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

    INT asnSignSize = 0;
    BYTE *asnsign = signToASN(signature->signature.ecdsa.signatureR.buffer,
                              signature->signature.ecdsa.signatureR.size,
                              signature->signature.ecdsa.signatureS.buffer,
                              signature->signature.ecdsa.signatureS.size,
                              &asnSignSize);

    printf("\n\nEphemeral Public Key");
    printf("\nX=");
    for (int i = 0; i < (inPoint).point.x.size; i++)
    {
        printf("%02x", (inPoint).point.x.buffer[i]);
    }
    printf("\nY=");
    for (int i = 0; i < (inPoint).point.y.size; i++)
    {
        printf("%02x", (inPoint).point.y.buffer[i]);
    }
    printf("\n\nThe shared key: Z point");
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

    printf("\n\nECC Signature (ASN.1 DER) = \n");
    for (int v = 0; v < asnSignSize; v++)
    {
        printf("%02x", asnsign[v]);
    }
    printf("\n\n");
}
