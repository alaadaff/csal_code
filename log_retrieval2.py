import server2
import encryptor2
import helpers
from random import randbytes
import pickle
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from time import process_time

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

srv = randbytes(16)
sid = randbytes(16)
chall = randbytes(16)
sigma = randbytes(256)
cert_pk, priv, pemk = helpers.generate_random_certificate()

pk1, sk1, pk_bytes1, sk_bytes1 = encryptor2.generate_key()
enc1_suite = encryptor2.generate_suite()
encap1, sender1 = enc1_suite.create_sender_context(pk1)

serial = encryptor2.getSerial()
cl = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Edg/120.0.100.0"}

symmK = encryptor2.generate_symmetric()
f = Fernet(symmK)
#combined = [serial, cl]
cDEM = f.encrypt(pickle.dumps([serial, cl]))
#cDEM = f.encrypt(pickle.dumps(combined))

cKEM = sender1.seal(cDEM)
sign, pem, pk_sign = generateSignature(cKEM)
sign1, pem1, pk_sign1 = generateSignature(cDEM)

T_log = [sid, srv, cDEM]
T_cert = [sid, chall, pk_bytes1, cert_pk, sigma, pemk]
#T_cert = [sid, chall, pk_bytes1, cert_pk, pemk]
T_kem = [sid, pk_bytes1, cKEM]

log_no_smuggle = [T_log, T_cert, T_kem, sid, sigma] #without smuggling

pickled_log = pickle.dumps(log_no_smuggle)

print("Size of log retrieved from server without smuggling: ", len(pickled_log))

symmk_smuggle = encryptor2.generate_symmetric()
f = Fernet(symmk_smuggle)
C_old = f.encrypt(symmk_smuggle)
T_old = [sid, C_old]

log_smuggle = [T_log, T_cert, T_kem, sid, sigma, T_old] #with smuggling
pickled_log_smuggle = pickle.dumps(log_smuggle)
print("Size of log retrieved from server with smuggling: ", len(pickled_log_smuggle))




