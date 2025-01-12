import sqlite3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import uuid
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
from random import randbytes
#import encryptor2

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



"""
def insert_row_encryptor(db_name, table_name):
  
    Insert a row into the specified SQLite table with generated sid and data.
    
    Args:
        db_name (str): The name of the SQLite database file.
        table_name (str): The name of the table into which data is being inserted.
   
    try:
        # Generate a unique sid (primary key) using UUID
        sid = str(uuid.uuid4())  # Generate a unique identifier for the sid
        user = "Bob"
        relyingParty = "facebook.com"
        suiteEnc = encryptor2.generate_suite()
        public, private, pk_bytes, sk_bytes = encryptor2.generate_key()
        symmK = encryptor2.generate_symmetric()
        encap, sender = suiteEnc.create_sender_context(public)
        
        # Connect to the SQLite database
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        # Prepare the SQL query with placeholders for variables
        sql = f"INSERT INTO {table_name} (sid, user, relyingParty, publicKeys, encapKeys, secretKeys, symmetricKeys) VALUES (?, ?, ?, ?, ?, ?, ?)"
        
        # Execute the query, passing the values as a tuple
        cursor.execute(sql, (sid, user, relyingParty, pk_bytes, encap, sk_bytes, symmK))
        
        # Commit the transaction
        conn.commit()
        
        print(f"Row inserted into '{table_name}' with sid = {sid}.")
        
    except sqlite3.IntegrityError as e:
        # Handle unique constraint violation or other integrity errors
        print(f"IntegrityError: {e}")
    except sqlite3.Error as e:
        # Catch any other SQLite errors
        print(f"SQLite Error: {e}")
    finally:
        # Close the connection to the database
        conn.close()


    #insert_row_encryptor('encryptor2.db', 'encryptor2')
 """


def insert_single_value(db_name, table_name, column_name, value):
    """
    Inserts a single value into a specified column of a table in an SQLite database.
    
    Args:
        db_name (str): The name of the SQLite database file.
        table_name (str): The name of the table where the value will be inserted.
        column_name (str): The name of the column where the value will be inserted.
        value (str): The value to insert into the column.
    """
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()
        
        # Prepare the SQL query with placeholders
        sql = f"INSERT INTO {table_name} ({column_name}) VALUES (?)"
        
        # Execute the query with the provided value
        cursor.execute(sql, (value,))
        
        # Commit the transaction
        conn.commit()
        
        print(f"Value '{value}' inserted into '{table_name}' table, column '{column_name}'.")
    
    except sqlite3.Error as e:
        # Catch any SQLite errors
        print(f"SQLite Error: {e}")
    
    finally:
        # Close the database connection
        conn.close()