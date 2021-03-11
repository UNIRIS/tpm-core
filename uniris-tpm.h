#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <tss2/tss2_esys.h>

#define ASN1_SEQ 0x30
#define ASN1_INT 0x02
#define ASN1_OID 0x06
#define ASN1_BitString 0x03
#define PRIME_LEN 32

typedef unsigned char BYTE;
typedef unsigned short INT;

static ESYS_CONTEXT *esys_context;
static bool isRootKey;
int rc;

static ESYS_TR rootKeyHandle;
static BYTE rootKeyASN[4 + 9 + 10 + 4 + PRIME_LEN + PRIME_LEN];
static INT rootKeySize;
static BYTE rootKeyHash[PRIME_LEN];

static ESYS_TR previousKeyHandle;
static ESYS_TR nextKeyHandle;

static INT previousKeyIndex;
static INT nextKeyIndex;

static ESYS_TR currentKeyHandle;

BYTE sigEccASN[2 + 2 + PRIME_LEN + 2 + PRIME_LEN + 2];

void initialize();
void updateHandlesIndexes();
BYTE *getPublicKey(INT index, INT *publicKeySize);
BYTE *signECDSA(INT index, BYTE *hashToSign, INT *eccSignSize);