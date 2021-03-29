#include <stdbool.h>
typedef unsigned char BYTE;
typedef unsigned short INT;

void initializeTPM(INT keyIndex);

INT getKeyIndex();
void setKeyIndex(INT keyIndex);

BYTE *getPublicKey(INT keyIndex, INT *publicKeySize);
BYTE *signECDSA(INT keyIndex, BYTE *hashToSign, INT *eccSignSize, bool increment);
