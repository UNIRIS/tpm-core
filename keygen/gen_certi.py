# pycryptodome required: sudo pip install pycryptodome
import os, shutil
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

f = open('uniris-ca.pem', 'rt')
signing_key = ECC.import_key(f.read())

for root, dirs, files in os.walk('keys', topdown=False):
    for name in files:
        key_file = os.path.join(name)
        os.mkdir('certificates/'+key_file)
        keys = open('keys/'+key_file, 'r').readlines()

        for key in keys:
            binary_key = bytes.fromhex(key)
            key_hash = SHA256.new(binary_key)

            uniris_ca = DSS.new(signing_key, 'fips-186-3', 'der')
            mini_certificate = uniris_ca.sign(key_hash)

            f = open('certificates/'+key_file+'/'+key_hash.hexdigest()+'.bin', 'wb')
            f.write(mini_certificate)
            f.close()
        
        shutil.make_archive('certificates/'+key_file, 'zip', 'certificates/'+key_file)
        shutil.rmtree('certificates/'+key_file)
