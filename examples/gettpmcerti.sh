#!/bin/sh

#*******************************************************************************
 #   Archethic TPM Library
 #   (c) 2021 Varun Deshpande, Uniris
 #
 #  Licensed under the GNU Affero General Public License, Version 3 (the "License");
 #  you may not use this file except in compliance with the License.
 #  You may obtain a copy of the License at
 #
 #      https://www.gnu.org/licenses/agpl-3.0.en.html
 #
 #  Unless required by applicable law or agreed to in writing, software
 #  distributed under the License is distributed on an "AS IS" BASIS,
 #  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 #  See the License for the specific language governing permissions and
 #  limitations under the License.
 #********************************************************************************

set -- $(tpm2_createek -c - -G ecc -u ek.key)
tpm2_evictcontrol -c $2

# response='{"pubhash":"5GvwfL1ze5qN4m75Q9m5-JURXwF7Q3JtnRKKfIsadg0%3D","certificate":"MIIEADCCA6WgAwIBAgIUNuLJ4Y4Tm-5hFaJ52fRbqH7AUGUwCgYIKoZIzj0EAwIwgZsxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTUwMwYDVQQLDCxUUE0gRUsgaW50ZXJtZWRpYXRlIGZvciBDTUxfRVBJRF9QUk9EIHBpZDoxMzEWMBQGA1UEAwwNd3d3LmludGVsLmNvbTAeFw0yMDAzMTMwMDAwMDBaFw00OTEyMzEyMzU5NTlaMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARfz0Gv0BxMjbibdLmpoeYXMepobSuhPtaq17Axi1ShbxDJv1PoyICmPGtbKqBilnbqy3dp3QkYgohuyXYyRfNXo4ICXzCCAlswDwYDVR0TAQH_BAUwAwEBADAOBgNVHQ8BAf8EBAMCBSAwEAYDVR0lBAkwBwYFZ4EFCAEwJQYDVR0JAQEABBswGTAXBgVngQUCEDEOMAwMAzIuMAIBAAICAIowUAYDVR0RAQH_BEYwRKRCMEAxFjAUBgVngQUCAQwLaWQ6NDk0RTU0NDMxDjAMBgVngQUCAgwDQ01MMRYwFAYFZ4EFAgMMC2lkOjAxRjQwMDBFMB8GA1UdIwQYMBaAFJqvWR7iY8quEPV7oE-o0d1mE_nrMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHBzOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50L0NSTC9la2NlcnQvQ01MRVBJRFBST0RfRUtfRGV2aWNlLmNybDB3BggrBgEFBQcBAQRrMGkwZwYIKwYBBQUHMAKGW2h0dHBzOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50L0NSTC9la2NlcnQvQ01MRVBJRFBST0RfRUtfUGxhdGZvcm1fUHVibGljX0tleS5jZXIwgbEGA1UdIASBqTCBpjCBowYKKoZIhvhNAQUCATCBlDBaBggrBgEFBQcCARZOaHR0cHM6Ly90cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML2VrY2VydC9FS2NlcnRQb2xpY3lTdGF0ZW1lbnQucGRmMDYGCCsGAQUFBwICMCoMKFRDUEEgVHJ1c3RlZCBQbGF0Zm9ybSBNb2R1bGUgRW5kb3JzZW1lbnQwCgYIKoZIzj0EAwIDSQAwRgIhAIpRvBGWM2RGW7BJfjxtYloAcikMSvPVxw2vhTYKcM7bAiEA9eOeNllvucn4SCBd6uOKi9cSTcWsL-1kQVoA0Zj-gfc%3D"}'
# echo $response > certificate.json

tpm2_getekcertificate https://ekop.intel.com/ekcertservice/ -V -u ek.key -o certificate.json

sed 's/-/+/g;s/_/\//g;s/%3D/=/g;s/^{.*certificate":"//g;s/"}$//g;' certificate.json |
    base64 --decode |
    openssl x509 -inform DER -outform PEM > certificate.pem

openssl x509 -in certificate.pem -text

rm ek.key certificate.json
