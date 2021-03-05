#include <stdio.h>
#include <tss2/tss2_esys.h>

#define ASN1_SEQ 0x30
#define ASN1_INT 0x02
#define ASN1_OID 0x06
#define ASN1_BitString 0x03
#define PRIME_LEN 32

typedef unsigned char BYTE;
typedef unsigned short INT;


void test();