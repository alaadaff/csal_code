#smuggle symmetric keys for older sessions to other devices that have not seen the session
import subprocess

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyhpke import (AEADId, CipherSuite, KDFId, KEMId, KEMInterface, KEMKey,
                    KEMKeyInterface, KEMKeyPair)

import encryptor2
import helpers

def smuggle():

    #best case scenario: encryptor does not have any old keys (usual login)
    #worst case: encryptor has old keys corresponding to number of ciphertexts, so can decrypt all ciphertexts

    all_keys = helpers.fetch_data('encryptor2.db', 'encryptor2', 'symmetricKeys')
    CKems = helpers.fetch_data('encryptor2.db', 'encryptor2', 'CKEMs')
    #decrypt all ciphertexts
    for i in range(len(all_keys)):
        encryptor2.decrypt()

