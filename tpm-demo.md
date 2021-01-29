# TPM Demo with ECC

```console
sudo su
```
## Capabilities
```console
tpm2_getcap -l
tpm2_getcap properties-fixed
```
## Random Bytes
```console
tpm2_getrandom --hex 20
```
## Generate Primary Keys
### Cannot be taken out? Can be used for sign/verify/enc/dec?
```console
tpm2_createprimary -h
tpm2_createprimary -C o -g sha256 -G ecc -c context.out
```
## Generate Primary Keys 
### With random data
```console
printf '\x20\x00' > ecc_param_buf_size
dd if=/dev/urandom bs=32 count=1 of=ecc_param_buf
cat ecc_param_buf_size ecc_param_buf> unique.dat
tpm2_createprimary -C o -g sha256 -G ecc -c context.out -u unique.dat
```
Everything is temporary unless stored.
## Persist/Store Keys on TPM
```console
tpm2_evictcontrol -C o -c context.out 0x81000000
```
## Read Public keys from TPM
```console
tpm2_getcap handles-persistent
tpm2_readpublic -c 0x81000000 -o ecc.key -f pem
cat ecc.key
```
## Delete Keys on TPM
```console
tpm2_evictcontrol -C o -c 0x81000000
tpm2_getcap handles-persistent
```
## Create Endorsement Keys
### Unique for each TPM-Key format, used for identifying the TPM?
```console
tpm2_createek -c - -G ecc -u ek.key -f pem
```
## Create attestation keys
### Can be taken out of TPM (including the private part)?
```console
tpm2_createak -C 0x81000000 -c attest.ctx -G ecc -u ak.key -f pem
```
## Store the attestion key in TPM
```console
tpm2_evictcontrol -c attest.ctx
tpm2_getcap handles-persistent
```
## Hash data
```console
echo "UNIRIS" > data.txt
cat data.txt
tpm2_hash -C e -g SHA256 -o hash.bin -t ticket.bin data.txt
tpm2_hash -g sha256 -o hashfile.bin -t metadata.ticket data.txt
```

## Create Primary Key (RSA)
### With random data
```console
dd if=/dev/urandom bs=96 count=1 status=none | tpm2_createprimary -C o -G ecc -g sha256 -c context.out -u - \
tpm2_createprimary -C o -g sha256 -G rsa -c context.out
printf '\x00\x01' > ud.1
dd if=/dev/zero bs=256 count=1 of=ud.2
cat ud.1 ud.2 > unique.dat
tpm2_createprimary -C o -g sha256 -G rsa -c context.out -u unique.dat
```
