#smuggle symmetric keys for older sessions to other devices that have not seen the session
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMKeyPair, KEMInterface, KEMKeyInterface
from cryptography.fernet import Fernet
import subprocess 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
import server2
import helpers
import encryptor2

def smuggle():

    all_keys = server2.fetch_data('encryptor2.db', 'encryptor2', 'symmetricKeys')
    #decrypt all ciphertexts

