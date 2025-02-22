import os
import sqlite3
import sys
from random import randbytes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import encryptor2
import helpers


def insert_row_encryptor(db_name, table_name):
    """
    Insert a row into the specified SQLite table with generated sid and data.
    
    Args:
        db_name (str): The name of the SQLite database file.
        table_name (str): The name of the table into which data is being inserted.
    """
    try:
        # Generate a unique sid (primary key) using UUID
        sid = randbytes(16)  # Generate a unique identifier for the sid
        user = "Bob"
        relyingParty = "facebook.com"
        suiteEnc = encryptor2.generate_suite()
        public, private, pk_bytes, sk_bytes = encryptor2.generate_key()
        symmK = encryptor2.generate_symmetric()
        encap, sender = suiteEnc.create_sender_context(public)
        
        # Connect to the SQLite database
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())

        sigK = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() 
        )

        # Prepare the SQL query with placeholders for variables
        sql = f"INSERT INTO {table_name} (sid, user, relyingParty, publicKeys, encapKeys, secretKeys, symmetricKeys, signingKeys) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        
        # Execute the query, passing the values as a tuple
        cursor.execute(sql, (sid, user, relyingParty, pk_bytes, encap, sk_bytes, symmK, sigK))
        
        # Commit the transaction
        conn.commit()
        
    except sqlite3.IntegrityError as e:
        # Handle unique constraint violation or other integrity errors
        print(f"IntegrityError: {e}")
    except sqlite3.Error as e:
        # Catch any other SQLite errors
        print(f"SQLite Error: {e}")
    finally:
        # Close the connection to the database
        conn.close()

if __name__ == '__main__':
    encryptor2.create_db_and_table('encryptor2.db')
    insert_row_encryptor('encryptor2.db', 'encryptor2')
    print("here")

    sid = helpers.fetch_data('encryptor2.db', 'encryptor2', 'sid')
    user = helpers.fetch_data('encryptor2.db', 'encryptor2', 'user')
    RP = helpers.fetch_data('encryptor2.db', 'encryptor2', 'relyingParty')
    pk = helpers.fetch_data('encryptor2.db', 'encryptor2', 'publicKeys')
    encap = helpers.fetch_data('encryptor2.db', 'encryptor2', 'encapKeys')
    sk = helpers.fetch_data('encryptor2.db', 'encryptor2', 'secretKeys')
    symmk = helpers.fetch_data('encryptor2.db', 'encryptor2', 'symmetricKeys')
    sigk = helpers.fetch_data('encryptor2.db', 'encryptor2', 'signingKeys')

    print(f"size of sid: {len(sid[0])}B")
    print(f"size of username: {sys.getsizeof(user[0])}B")
    print(f"size of RP: {sys.getsizeof(RP[0])}B")
    print(f"size of enc_pk: {len(pk[0])}B")
    print(f"size of encap key: {len(encap[0])}B")
    print(f"size of enc_sk: {len(sk[0])}B")
    print(f"size of symmetric key: {len(symmk[0])}B")
    print(f"size of signing sk: {len(sigk[0])}B")

    os.system(f'rm encryptor2.db')
    

#ls -l encryptor2.db --> size of db 