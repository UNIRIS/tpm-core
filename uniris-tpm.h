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
#define ANS1_MAX_KEY_SIZE 4 + 9 + 10 + 4 + PRIME_LEN + PRIME_LEN

typedef unsigned char BYTE;
typedef unsigned short INT;

static ESYS_CONTEXT *esys_context;
int rc;

static ESYS_TR rootKeyHandle;
static BYTE rootKeyASN[ANS1_MAX_KEY_SIZE];
static INT rootKeySizeASN;
static BYTE rootKeyHash[PRIME_LEN];

static ESYS_TR previousKeyHandle;
static BYTE previousKeyASN[ANS1_MAX_KEY_SIZE];
static INT previousKeySizeASN;
static INT previousKeyIndex;

static ESYS_TR nextKeyHandle;
static BYTE nextKeyASN[ANS1_MAX_KEY_SIZE];
static INT nextKeySizeASN;
static INT nextKeyIndex;

static ESYS_TR currentKeyHandle;
static TPM2B_PUBLIC *currentKeyTPM = NULL;
static BYTE currentKeyASN[ANS1_MAX_KEY_SIZE];
static INT currentKeySizeASN;

BYTE sigEccASN[2 + 2 + PRIME_LEN + 2 + PRIME_LEN + 2];

void initializeTPM(INT index);
void setRootKey();
void setKeyIndex(INT index);
INT getKeyIndex();
void updateHandlesIndexes();
void generatePublicKey(INT index);

BYTE *getPublicKey(INT index, INT *publicKeySize);
BYTE *signECDSA(INT index, BYTE *hashToSign, INT *eccSignSize);