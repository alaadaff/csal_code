import sys
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
import socket
import json
import ast

import sqlite3
from random import randbytes
import os
import errno
import pickle  
import ast
from time import process_time
import subprocess
import sqlite3
import simulator
import random  
import helpers
import time
import server2


sessionId = random.randint(1, 10)

def create_db_and_table(db_name):
    # Connect to the SQLite database (it will be created if it doesn't exist)
    conn = sqlite3.connect(db_name)

    # Create a cursor object to interact with the database
    cursor = conn.cursor()

    # Create a table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS encryptor2 (
        sid INTEGER PRIMARY KEY,
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


def prcoess_data_encryptor():

    #process data received from server and extract set of public keys
    
    #generate encryptor params and forward to client
    sessionId = random.randint(1, 100)
    simulator.insert_into_single_column ('encryptor2.db', 'encryptor2', 'sid', [sessionId])

    public, private = generate_key()
    simulator.insert_into_single_column ('encryptor2.db', 'encryptor2', 'publicKeys', [public])
    simulator.insert_into_single_column ('encryptor2.db', 'encryptor2', 'secretKeys', [private])

    symmK = generate_symmetric()
    simulator.insert_into_single_column ('encryptor2.db', 'encryptor2', 'symmetricKeys', [symmK])



    #certA = server2.generate_random_certificate()
    #sign = generateSignature(certA)

    encryptor_payload =  [sessionId, public, private, symmK]
    encryptor_payload_serialize = pickle.dumps(encryptor_payload)

    return encryptor_payload_serialize

  


# Function to process data sent from client via pipes 
def process_data_client():

   # Read the message from stdin (in bytes)
    byte_message = sys.stdin.buffer.read()  # Read bytes from stdin #this is somehow string
    #print(type(byte_message))
    # Optionally print the raw byte message (for debugging)
    #print(f"Receiver (raw received bytes): {byte_message}")
    #print(type(byte_message))
    # Decode the byte message to string for processing
    #message = byte_message.decode('utf-8')
    if byte_message:
        message = pickle.loads(byte_message)
        #function to process received message 

        print(message)

    # Print the received message in the receiver's terminal
    #print(f"Receiver (received): {message}")
    
    # Process the message and create a response - response has to be in string format
    #response = f"Processed: {pickle.loads(message)}"
    #response = f"Processed: {message}"
    response = prcoess_data_encryptor()

    # Print the response in receiver's terminal
    #print(f"Receiver (response): {response}")
    
    # Convert the response to bytes and send it back to sender's stdout
    #sys.stdout.write(response.encode('utf-8') + b'\n')  # Write response as bytes
    sys.stdout.buffer.write(response)  # Write response as bytes
    sys.stdout.flush()  # Ensure the response is flushed



def getSerial():

    cmd = "system_profiler SPHardwareDataType | awk '/Serial Number/ {print $4}'"
    result = subprocess.run(cmd, stdout=subprocess.PIPE, shell=True, check=True)
    serial_number = result.stdout.strip()
    return serial_number 


def generate_symmetric(): #base64 encoded 32-byte key
    
    key = Fernet.generate_key()
    #f = Fernet(key) #this can be called anytime encryption or decryption is required once the key exists 
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
    sk = key_pair.private_key
    sk_serialize = sk.to_private_bytes()

    return pk_serialize, sk_serialize


def encrypt_csal():
    enc_suite = generate_suite()
    pubK, secK = generate_key()
    symmK = generate_symmetric()
    serial = getSerial()
    token = Fernet(symmK).encrypt(serial)
    encap, sender = enc_suite.create_sender_context(pubK)
    ctxt = sender.seal(token)

    #serialize before inserting into db
    pubK_serialize = pickle.dumps(pubK)
    secK_serialize = pickle.dumps(secK)
    symmK_serialize = pickle.dumps(symmK)
    encap_serialize = pickle.dumps(encap) 

    #insert into db
    simulator.insert_into_single_column ('encryptor2.db', 'encryptor2', 'publicKeys', [pubK_serialize])
    simulator.insert_into_single_column ('encryptor2.db', 'encryptor2', 'secretKeys', [secK_serialize])
    simulator.insert_into_single_column ('encryptor2.db', 'encryptor2', 'symmetricKeys', [symmK_serialize])
    simulator.insert_into_single_column ('encryptor2.db', 'encryptor2', 'encapKeys', [encap_serialize])

    #return ctxt, encap, puk, sck
    return ctxt 


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
    return signature  


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
    #create_db_and_table('encryptor.db')
    create_db_and_table('encryptor2.db')
    process_data_client()

    """

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

