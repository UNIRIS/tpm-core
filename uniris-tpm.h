/*******************************************************************************
 *   Archethic TPM Library
 *   (c) 2021 Varun Deshpande, Uniris
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

#include <stdbool.h>
typedef unsigned char BYTE;
typedef unsigned short INT;

void initializeTPM(INT keyIndex);

BYTE *getPublicKey(INT keyIndex, INT *publicKeySize);
BYTE *signECDSA(INT keyIndex, BYTE *hashToSign, INT *eccSignSize, bool increment);

INT getKeyIndex();
void setKeyIndex(INT keyIndex);

BYTE *getECDHPoint(INT keyIndex, BYTE *euphemeralKey);
