from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

f = open('uniris-ca.pem','rt')
signing_key = ECC.import_key(f.read())

keys = open('keys.txt', 'r').readlines()

for key in keys:
    binary_key = bytes.fromhex(key)
    key_hash = SHA256.new(binary_key)

    uniris_ca = DSS.new(signing_key,'fips-186-3','der')
    mini_certificate = uniris_ca.sign(key_hash)

    f = open('certificates/'+key_hash.hexdigest()+'.bin', 'wb')
    f.write(mini_certificate)
    f.close()
