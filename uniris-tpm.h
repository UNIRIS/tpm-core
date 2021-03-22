#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef unsigned char BYTE;
typedef unsigned short INT;

void initializeTPM(INT keyIndex);
void setRootKey();
void setKeyIndex(INT keyIndex);
INT getKeyIndex();
void updateHandlesIndexes();
void generatePublicKey(INT keyIndex);

BYTE *getPublicKey(INT keyIndex, INT *publicKeySize);
BYTE *signECDSA(INT keyIndex, BYTE *hashToSign, INT *eccSignSize);