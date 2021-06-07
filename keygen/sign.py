from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import time

#key = ECC.generate(curve='P-256')
#f = open('myprivatekey.pem','wt')
#f.write(key.export_key(format='PEM'))
#f.close()

f = open('myprivatekey.pem','rt')
key = ECC.import_key(f.read())
message = b'UNIRIS'
h = SHA256.new(message)
print (h.hexdigest())


a = time.time()
for i in range(500):
    signer = DSS.new(key,'fips-186-3','der')
    signature = signer.sign(h)
    f = open(h.hexdigest()+'.bin', 'wb')
    f.write(signature)
    f.close()
print(time.time()-a)

