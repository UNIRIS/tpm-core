#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>

#define ASN1_SEQ 0x30
#define ASN1_INT 0x02
#define ASN1_OID 0x06
#define ASN1_BitString 0x03
#define PRIME_LEN 32

typedef unsigned char BYTE;
typedef unsigned short INT;

BYTE pubKeyASN[4 + 9 + 10 + 4 + PRIME_LEN + PRIME_LEN];
BYTE sigEccASN[2 + 2 + PRIME_LEN + 2 + PRIME_LEN + 2];

static ESYS_CONTEXT *esys_context;
static ESYS_TR session;
int rc;
void initialize();
void setSession();
BYTE *getPublicKey(INT *publicKeySize);