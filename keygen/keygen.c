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

/*  Compile:
    gcc keygen.c -o keygen uniris-tpm.c -ltss2-esys -lcrypto

    Keygen:
    sudo ./keygen > keys.txt
*/

#include <stdio.h>
#include <openssl/sha.h>
#include "../uniris-tpm.h"

void main()
{
    initializeTPM(1);

    INT publicKeySize = 0;
    BYTE *asnkey;

    for (int z = 0; z < 500; z++)
    {
        asnkey = getPublicKey(z, &publicKeySize);
        for (int v = 26; v < publicKeySize; v++)
        {
            printf("%02x", asnkey[v]);
        }
        printf("\n");
    }
}
