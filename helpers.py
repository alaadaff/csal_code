import sqlite3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def serialize_public_key(public_key):
    # Serialize the EC public key to PEM format (you can also use DER if preferred)
    pem = public_key.to_public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def deserialize_public_key(serialized_public_key):
    # Deserialize the PEM to an ECPublicKey object
    public_key = serialization.load_pem_public_key(serialized_public_key)
    return public_key


def serialize_rsa_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem


# Step 2: Deserialize RSA Private Key
def deserialize_rsa_private_key(serialized_private_key):
    private_key = serialization.load_pem_private_key(serialized_private_key, password=None)
    return private_key