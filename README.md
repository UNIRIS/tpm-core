# TPM Core

## Depends on [TPM2-TSS](https://github.com/tpm2-software/tpm2-tss)

## Compiling the library

```console
gcc uniris-tpm.c -o uniris-tpm -ltss2-esys -c
```

## Testing with a driver

```console
gcc driver.c -o driver uniris-tpm -ltss2-esys
sudo ./driver
```

## One step driver compilation

```console
gcc driver.c -o driver uniris-tpm.c -ltss2-esys
sudo ./driver
```

## Compiling TPM-core for Elixir support

Make sure that Erlang and Elixir are already installed on the system.

```console
gcc support.c -o support stdio_helpers.c uniris-tpm.c -ltss2-esys
```

## Required commands at the start of a new session

```console
sudo iex tpm-lib.ex
TPMPort.start_link
TPMPort.initialize_tpm(KEY_INDEX)
```

## Library Functions for Elixir support

```console
TPMPort.get_public_key(KEY_INDEX)
TPMPort.sign_ecdsa(KEY_INDEX, HASH_SHA256)
TPMPort.get_key_index()
TPMPort.set_key_index(KEY_INDEX)
```

## Testing

```console
sudo iex tpm-lib.ex
TPMPort.start_link
TPMPort.initialize_tpm(10)
public_key = TPMPort.get_public_key(10)
hash256 = :crypto.hash(:sha256, "UNIRIS")
sign = TPMPort.sign_ecdsa(10, hash256)
:crypto.verify(:ecdsa, :sha256, "UNIRIS", sign, [public_key, :secp256r1])
{eph_pub, eph_pv} = :crypto.generate_key(:ecdh, :secp256r1)
:crypto.compute_key(:ecdh, public_key, eph_pv, :secp256r1) 
TPMPort.get_ecdh_point(10, eph_pub) 
```
