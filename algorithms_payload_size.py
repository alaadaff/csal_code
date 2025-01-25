
import server2
import encryptor2
from random import randbytes
import pickle
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from time import process_time

cl = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Edg/120.0.100.0"}
serial = encryptor2.getSerial()

def generateSignature(blob): 
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

if __name__ == '__main__':
    print("Payload for a single-entry re-encryption request:")
    print("-------------------------------------------------")
    cert_encryptor, _ = server2.generate_random_certificate()
    cert_srv, _ = server2.generate_random_certificate()

    i = randbytes(16)
    chall_i = randbytes(16)
    sign_i = randbytes(256) # signatures have the same length independently of the content
    pk_i, sk_i, pkbyt_i, skbyt_i = encryptor2.generate_key()

    j = randbytes(16)
    chall_j = randbytes(16)
    sign_j = randbytes(256)
    pk_j, sk_j, pkbyt_j, skbyt_j = encryptor2.generate_key()

    chall = randbytes(16)

    enc_suite = encryptor2.generate_suite()
    encap, sender = enc_suite.create_sender_context(pk_i)
    symmk_i = encryptor2.generate_symmetric()
    C_kem = sender.seal(symmk_i)
    signature_kem, _, _ = generateSignature(C_kem)
    kem = (C_kem, signature_kem)

    L=[(i, j, pkbyt_j, kem)]
    T_cert = [[i, chall_i, pkbyt_i, cert_encryptor, sign_i], [j, chall_j, pkbyt_j, cert_encryptor, sign_j]]
    sigma_reenc = generateSignature(pickle.dumps((i, chall, L, T_cert)))

    print(f"Server -> client payload: {len(i)+len(chall)+len(L)+sys.getsizeof(T_cert)+len(sigma_reenc)}B.")
    print(f"Client -> encryptor payload is the same as server -> client.")

    L_Kem = [(i, j, kem)] # assuming same size for another KEM
    print(f"Encryptor -> client payload: {sys.getsizeof(L_Kem)}B.")
    
    print("\n\nPayload for an action request:")
    print("------------------------------")
    sid_action = randbytes(16)
    chall_action = randbytes(16)
    sigma_action, _, _ = generateSignature(pickle.dumps((sid_action, chall_action)))

    print(f"Server -> client payload: {len(sid_action)+len(chall_action)+len(sigma_action)}B.")
    
    print(f"Client -> encryptor payload: {len(sid_action)+len(chall_action)+len(sigma_action)+ sys.getsizeof(cl)}B.")

    symmk_action = encryptor2.generate_symmetric()
    f = Fernet(symmk_action)
    cdem = f.encrypt(pickle.dumps([serial, cl]))

    print(f"Encryptor -> client payload: {len(sid_action)+len(cdem)}B.")


