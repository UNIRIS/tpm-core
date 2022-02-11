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

/* Gets 20 bytes from TPM,
   finally prints it.
   Executes:
   Esys_Initialize()
   Esys_GetRandom()
   Compile: gcc random-gen.c -ltss2-esys -o random-gen
*/

#include <stdio.h>
#include <stdlib.h>
#include <tss2/tss2_esys.h>

int main()
{

    TSS2_RC r;

    /* Initialize the ESAPI context */
    ESYS_CONTEXT *ctx;
    r = Esys_Initialize(&ctx, NULL, NULL);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\nError: Esys_Initialize\n");
        exit(1);
    }

    /* Get random data */
    TPM2B_DIGEST *random_bytes;
    r = Esys_GetRandom(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 20,
                       &random_bytes);

    if (r != TSS2_RC_SUCCESS)
    {
        printf("\nError: Esys_GetRandom\n");
        exit(1);
    }

    printf("\n");
    for (int i = 0; i < random_bytes->size; i++)
    {
        printf("0x%x ", random_bytes->buffer[i]);
    }
    printf("\n");
    exit(0);
}
