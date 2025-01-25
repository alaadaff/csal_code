
import server2
import encryptor2
from random import randbytes
import pickle
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from time import process_time


#a single client that comes online after the first client and has a ckem with the client

def generateSignature(blob): 

    #example of blob is: pk_sid - ctxt and pkset not included 

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


    public_key = private_key.public_key()
    

    pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    #format=serialization.PublicFormat.OpenSSH
    )


    signature = private_key.sign(
        blob,
        padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
                 ),
         hashes.SHA256()
    )
    
    #attst_stmt = AttestationResponse.from_dict(signature)
    return [signature, pem, public_key] 


def sign_verify(pk, signature, message):
    
    return pk.verify(
    signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )


serial = encryptor2.getSerial()
cl = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Edg/120.0.100.0"}

sid = randbytes(16)
chall = randbytes(16)
sigma = randbytes(256)
sigma = randbytes(256)
cert, skk = server2.generate_random_certificate()

pk, sk, pkbyt, skbyt = encryptor2.generate_key()
enc_suite = encryptor2.generate_suite()
encap, sender = enc_suite.create_sender_context(pk)
symmk = encryptor2.generate_symmetric()
f = Fernet(symmk)
cdem = f.encrypt(pickle.dumps([serial, cl]))

ckem = sender.seal(cdem)
L = [ckem, ckem]
print(len(pickle.dumps(L)))


T_cert = [sid, chall, pkbyt, cert, sigma, sid, chall, pkbyt, cert, sigma]
blob_sign = [sid, chall, L, T_cert]
pald = [sid, chall, L, T_cert, sigma]
#T_cert = [sid, chall, pk_bytes, cert_pk, sigma]

#print(len(pickle.dumps(pald)))
