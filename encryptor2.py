import ast
import base64
import errno
import json
import os
import pickle
import random
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from random import randbytes
from time import process_time

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyhpke import (AEADId, CipherSuite, KDFId, KEMId, KEMInterface, KEMKey,
                    KEMKeyInterface, KEMKeyPair)

import helpers

sessionId = random.randint(1, 10)

def create_db_and_table(db_name):
    # Connect to the SQLite database (it will be created if it doesn't exist)
    conn = sqlite3.connect(db_name)

    # Create a cursor object to interact with the database
    cursor = conn.cursor()

    # Create a table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS encryptor2 (           
        sid BLOB PRIMARY KEY,
        user TEXT,
        relyingParty TEXT,
        publicKeys BLOB,
        encapKeys BLOB,
        secretKeys BLOB,
        symmetricKeys BLOB
    )
    ''')

    #Try insert into db
    #cursor.execute("INSERT INTO server (publicKeys) VALUES (?)", ('\x04e\xed\xa5\xa1%w\xc2\xba\xe8)C\x7f\xe38p\x1a',))

    # Commit the changes and close the connection
    conn.commit()
    conn.close()


def process_data_encryptor():

    #process data received from server and extract set of public keys
    
    #generate encryptor params and forward to client
    
    
    Ckem, Cdem = encrypt_csal()
    sessID = helpers.fetch_data('encryptor2.db', 'encryptor2', 'sid')
    pk_payload = helpers.fetch_data('encryptor2.db', 'encryptor2', 'publicKeys')
    sign, certA = generateSignature(pickle.dumps([sessID[0], pk_payload[0]]))

    #certA = server2.generate_random_certificate()
    #sign = generateSignature(certA)

    encryptor_payload = [sessID[0], pk_payload[0], Ckem, Cdem, sign, certA]
    encryptor_payload_serialize = pickle.dumps(encryptor_payload)

    return encryptor_payload_serialize

  


# Function to process data sent from client via pipes 
def process_data_client():

   # Read the message from stdin (in bytes)
    byte_message = sys.stdin.buffer.read()  # Read bytes from stdin #this is somehow string
    print(len(byte_message))
    #print(type(byte_message))
    # Optionally print the raw byte message (for debugging)
    #print(f"Receiver (raw received bytes): {byte_message}")
    #print(type(byte_message))
    # Decode the byte message to string for processing
    #message = byte_message.decode('utf-8')
    """
    if byte_message:
        message = pickle.loads(byte_message)
        #function to process received message 

        print(message[0])
    """
    
    # Print the received message in the receiver's terminal
    #print(f"Receiver (received): {message}")
    
    # Process the message and create a response - response has to be in string format
    #response = f"Processed: {pickle.loads(message)}"
    #response = f"Processed: {message}"
    response = process_data_encryptor()

    # Print the response in receiver's terminal
    #print(f"Receiver (response): {response}")
    
    # Convert the response to bytes and send it back to sender's stdout
    #sys.stdout.write(response.encode('utf-8') + b'\n')  # Write response as bytes
    sys.stdout.buffer.write(response)  # Write response as bytes
    sys.stdout.flush()  # Ensure the response is flushed


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
        suiteEnc = generate_suite()
        public, private, pk_bytes, sk_bytes = generate_key()
        symmK = generate_symmetric()
        #encap, sender = suiteEnc.create_sender_context(public)
        
        # Connect to the SQLite database
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        # Prepare the SQL query with placeholders for variables
        sql = f"INSERT INTO {table_name} (sid, user, relyingParty, publicKeys, secretKeys, symmetricKeys) VALUES (?, ?, ?, ?, ?, ?)"
        
        # Execute the query, passing the values as a tuple
        cursor.execute(sql, (sid, user, relyingParty, pk_bytes, sk_bytes, symmK))
        
        # Commit the transaction
        conn.commit()
        
        #print(f"Row inserted into '{table_name}' with sid = {sid}.")
        
    except sqlite3.IntegrityError as e:
        # Handle unique constraint violation or other integrity errors
        print(f"IntegrityError: {e}")
    except sqlite3.Error as e:
        # Catch any other SQLite errors
        print(f"SQLite Error: {e}")
    finally:
        # Close the connection to the database
        conn.close()

def getSerial():

    cmd = "system_profiler SPHardwareDataType | awk '/Serial Number/ {print $4}'"
    result = subprocess.run(cmd, stdout=subprocess.PIPE, shell=True, check=True)
    serial_number = result.stdout.strip()
    return serial_number 


def generate_symmetric(): #base64 encoded 32-byte key

    key = Fernet.generate_key()
    f = Fernet(key) #this can be called anytime encryption or decryption is required once the key exists 

    return key

# we'll need to generate a suite for both sealing and opening data encrypted using hpke 
def generate_suite():

    suite = CipherSuite.new(
    KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM
    )

    return suite


def generate_key():  

    suite = generate_suite()
    key_pair = suite.kem.derive_key_pair(randbytes(32))
    pk = key_pair.public_key
    pk_serialize = pk.to_public_bytes()
    #pk_serialize = helpers.serialize_public_key(pk)
    sk = key_pair.private_key
    sk_serialize = sk.to_private_bytes()
    #sk_serialize = helpers.serialize_public_key(pk)

    return pk, sk, pk_serialize, sk_serialize


def encrypt_csal():

    serial = getSerial()
    cl = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Edg/120.0.100.0"}
    serial = serial + pickle.dumps(cl)
    enc_suite = generate_suite()
    fetch1 = helpers.fetch_data('encryptor2.db', 'encryptor2', 'publicKeys')
    public = enc_suite.kem.deserialize_public_key(fetch1[0])
    encap, sender = enc_suite.create_sender_context(public)
    #helpers.insert_single_value('encryptor2.db', 'encryptor2', 'encapKeys', encap)
    #fetch3 = helpers.fetch_data('encryptor2.db', 'encryptor2', 'encapKeys')


    fetch2 = helpers.fetch_data('encryptor2.db', 'encryptor2', 'symmetricKeys')
    token = Fernet(fetch2[0])
    
    C_dem = token.encrypt(serial)
   

    #print(C_dem)
    #print("token type:", base64.urlsafe_b64decode(C_dem)[0])
    C_kem = sender.seal(fetch2[0])
    sender.seal(serial)
    
    return C_dem, C_kem


def decrypt_csal(ciphertext):

    dec_suite = generate_suite()
    fetch3 = helpers.fetch_data('encryptor2.db', 'encryptor2', 'secretKeys')
    sk = dec_suite.kem.deserialize_private_key(fetch3[0])
    recipient = dec_suite.create_recipient_context(encap, sk)

    ptxt1 = recipient.open(C_kem)
    ptxt2 = token.decrypt(C_dem)

    print(ptxt2)



def decrypt_csal(ctxt):
    dec_suite = generate_suite()



# Function to generate digital signatures before sending data to the client
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
    
    #returns signature, the digital certificate in pem format and the corresponding public key 
    #we can choose to include or not include the public key as it's supposedly already included in the PEM cert and can be extracted using openssl 
    return signature, pem  


#verifies digital signature 
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



if __name__ == "__main__":
   
    create_db_and_table('encryptor2.db')
    insert_row_encryptor('encryptor2.db', 'encryptor2')
    # print("inside encryptor")
    # CDEM, CKEM = encrypt_csal()
    # print(len(CDEM))
    # print(len(CKEM))

    # generate_symmetric()

    process_data_client()
    #process_data_encryptor()
    """
    helpers.insert_single_value('encryptor2.db', 'encryptor2', 'encapKeys', encap)
    suite = generate_suite()
    public, private = generate_key()

    pk_bytes = public.to_public_bytes()
    simulator.insert_into_single_column ('encryptor2.db', 'encryptor2', 'publicKeys', [pk_bytes])
    data = simulator.fetch_data('encryptor2.db', 'encryptor2', 'publicKeys')
    #print(data[0])
    #print(data[0][0])
    #print(type(data[0][0]))

    data_des = suite.kem.deserialize_public_key(data[0])
    #public = helpers.deserialize_public_key(data[0][0])
    print(data_des)
    print(type(data_des))
  
    encap, sender = suite.create_sender_context(data_des)
    ctxt = sender.seal(b"Hello, world!")

    recipient = suite.create_recipient_context(encap, private)
    message = recipient.open(ctxt)
    print(message)
    
    """

