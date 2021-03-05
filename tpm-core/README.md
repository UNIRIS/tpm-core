# TPM Core
## Depends on [TPM2-TSS](https://github.com/tpm2-software/tpm2-tss)

## Compiling the library
```console
gcc uniris-tpm.c -o uniris-tpm -ltss2-esys -c
```

## Testing with a driver
```console
gcc driver.c -o driver uniris-tpm
sudo ./driver
```

## One step driver compilation
```console
gcc driver.c -o driver uniris-tpm.c -ltss2-esys
sudo ./driver
```