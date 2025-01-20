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
#params retrieved from the server for log retrieval 
#retrieve rows from each of the dbs
#verify signatures 
#decrypt


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

#server sends the following:

"""
sid = randbytes(16)
cert = generate_random_certificate()
log = SRV + csal_decrypt(junk)
sign = 256 

T_log = sid, C_dem, SRV
T_old = sid, C_old
T_cert = sid, N, pk_sid, cert_A, sigma 
T_kem = sid, i, pk_sid, c_kem, 

"""
#log retrieval with no smuggling



ckem, cdem = encryptor2.encrypt_csal()
pk, sk, pk_bytes, sk_bytes = encryptor2.generate_key()
enc_suite = encryptor2.generate_suite()
encap, sender = enc_suite.create_sender_context(pk)

srv = randbytes(16)
sid = randbytes(16)
chall = randbytes(16)
sigma = randbytes(256)
cert_pk, priv = server2.generate_random_certificate()
symmk = encryptor2.generate_symmetric()
f = Fernet(symmk)
C_old = f.encrypt(symmk)
T_old = [sid, C_old]

#T_log = [sid, srv, cdem]
#T_cert = [sid, chall, pk_bytes, cert_pk, sigma]
#T_kem = [sid, pk_bytes, ckem]
#sid, sigma
#one_log = [T_log, T_cert, T_kem, sid, sigma, T_old] #with smuggling
#one_log = [T_log, T_cert, T_kem, sid, sigma] #without smuggling

#pickled_log = pickle.dumps(one_log)
#print(len(pickled_log))
#print(T_cert)

bes = b"helloo"
sigg, pemk, pak = generateSignature(bes)

T_log = [sid, srv, cdem]
T_cert = [sid, chall, pk_bytes, cert_pk, sigma, pemk]
T_kem = [sid, pk_bytes, ckem]
#sid, sigma
#one_log = [T_log, T_cert, T_kem, sid, sigma, T_old] #with smuggling
one_log = [T_log, T_cert, T_kem, sid, sigma] #without smuggling

pickled_log = pickle.dumps(one_log)
#print(len(pickled_log))


#decryption and verify signatures
# sends the pk_pem to verify signature once in T_cert but verifies signature twice, once for T_kem and the other for T_old 



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





############

#sign, pem, pk_sign = generateSignature(ckem)
pk1, sk1, pk_bytes1, sk_bytes1 = encryptor2.generate_key()
enc1_suite = encryptor2.generate_suite()
encap1, sender1 = enc1_suite.create_sender_context(pk1)

serial = encryptor2.getSerial()
cl = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Edg/120.0.100.0"}

symmK = encryptor2.generate_symmetric()
f = Fernet(symmK)
cDEM = f.encrypt(pickle.dumps([serial, cl]))

cKEM = sender1.seal(cDEM)
sign, pem, pk_sign = generateSignature(cKEM)
sign1, pem1, pk_sign1 = generateSignature(cDEM)

def decrypt_sign():

    pickle.loads(pickled_log)

    #encapsualted keys recovery from T_kem

    dec_suite = encryptor2.generate_suite()
    recipient = dec_suite.create_recipient_context(encap1, sk1)
    

    sign_verify(pk_sign, sign, cKEM)
    K = recipient.open(cKEM)
    sign_verify(pk_sign1, sign1, K)
    ptxt = f.decrypt(K)
    print(pickle.loads(ptxt))


def main():

    decrypt_sign()



if __name__ == "__main__":  

    avg = []

    for i in range(10):

        t1_start = process_time()

        main()

        t1_stop = process_time()
        print(t1_stop - t1_start)
        avg.append(t1_stop-t1_start)
    
        #print("Elapsed time during the whole program in seconds:", t1_stop-t1_start)
        #print(avg)

    final_avg = sum(avg) / len(avg)
    print(final_avg)