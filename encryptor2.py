import argparse
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
import server2

def create_db_and_table(db_name):
    # Connect to the SQLite database (it will be created if it doesn't exist)
    conn = sqlite3.connect(db_name)

    # Create a cursor object to interact with the database
    cursor = conn.cursor()

    # Create a table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS encryptor2 (           
        sid BLOB,
        user TEXT,
        relyingParty TEXT,
        publicKeys BLOB,
        encapKeys BLOB,
        secretKeys BLOB,
        symmetricKeys BLOB,
        signingKeys BLOB
    )
    ''')

    # Commit the changes and close the connection
    conn.commit()
    conn.close()

def insert_row_encryptor(db_name, table_name):
    """
    Insert a row into the specified SQLite table with generated sid and data.
    
    Args:
        db_name (str): The name of the SQLite database file.
        table_name (str): The name of the table into which data is being inserted.
    """
    try:
        # Generate a unique sid (primary key) using randbytes
        sid = randbytes(16)
        user = "Bob"
        relyingParty = "facebook.com"
        # suiteEnc = generate_suite()
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
    return sid

def process_data_encryptor_encrypt(chall, publicKeys=[], tKems=[], session=[]):

    
    
    sidd = insert_row_encryptor('encryptor2.db', 'encryptor2')
    #Ckem, Cdem, pem_ctxt = encrypt_csal(sid, cl, publicKeys, session)
    Ckem, Cdem, signs, pem = encrypt_csal(sidd, publicKeys, session)
    sessID = helpers.fetch_data('encryptor2.db', 'encryptor2', 'sid')
    pk_payload = helpers.fetch_data('encryptor2.db', 'encryptor2', 'publicKeys')
    sign1 = [chall, sessID, pk_payload]
    sign1_pickled = pickle.dumps(sign1)
    sigma, pk_pem = generateSignature(sign1_pickled)

    certA, sk = server2.generate_random_certificate()
    #sign = generateSignature(certA)

    encryptor_payload = [sessID, pk_payload, Ckem, Cdem, sigma, certA, pk_pem, signs, pem]
    encryptor_payload_serialize = pickle.dumps(encryptor_payload)

    return encryptor_payload_serialize



def process_data_encryptor_smuggle(chall, publicKeys=[], tKems=[], tdems =[], session=[]):

    #process data received from server and extract set of public keys
    
    sidd = insert_row_encryptor('encryptor2.db', 'encryptor2')
    lg, cold = decrypt_csal(tKems, tdems, session)
    symmk = helpers.fetch_value_by_primary_key('encryptor2.db', 'encryptor2', 'symmetricKeys', 'sid', sidd)
    token = Fernet(symmk)
    C_old = token.encrypt(pickle.dumps(cold))

    Ckem, Cdem, signs, pem = encrypt_csal(sidd, publicKeys, session)
    sessID = helpers.fetch_data('encryptor2.db', 'encryptor2', 'sid')
    pk_payload = helpers.fetch_data('encryptor2.db', 'encryptor2', 'publicKeys')
    sign1 = [chall, sessID, pk_payload]
    sign1_pickled = pickle.dumps(sign1)
    sigma, pk_pem = generateSignature(sign1_pickled)

    certA, sk = server2.generate_random_certificate()
    #sign = generateSignature(certA)

    encryptor_payload = [sessID, pk_payload, Ckem, Cdem, C_old, sigma, certA, pk_pem, signs, pem]
    encryptor_payload_serialize = pickle.dumps(encryptor_payload)

    return encryptor_payload_serialize





# Function to process data sent from client via pipes 
def process_data_client_login():

   # Read the message from stdin (in bytes)
    try:
        byte_message = sys.stdin.buffer.read()
        #print("Received byte message:", byte_message, flush=True)
    except Exception as e:
        print(f"Error occurred: {e}", flush=True)


    if byte_message:

        try:
            challenge_server = None
            pks = None
            tkems = None
            session_id = None
            tdems = None
            unpickle = pickle.loads(byte_message)
            serv_payld = unpickle[0]
            cl = unpickle[1]
        
            #print("Decoded message:", unpickle, flush=True)
            server_payload = pickle.loads(serv_payld) # [0] is payload & [1] is sigma
           
            server_payload1 = server_payload[0]
            server_payload1_unpickled = pickle.loads(server_payload1)
            
            challenge_server = server_payload1_unpickled[0]
            pks = server_payload1_unpickled[3]
        
            tkems = server_payload1_unpickled[4]
            
            session_id = server_payload1_unpickled[5]

            tdems = server_payload1_unpickled[6]

        except pickle.UnpicklingError as e:
            print("Error unpickling data:", e, flush=True)
        except UnboundLocalError:
            challenge_server = randbytes(16)
    

    sys.stdin.flush()  # flush stdin after reading in input 
    
    response = process_data_encryptor_encrypt(challenge_server, pks, tkems, session_id)
    
    # Convert the response to bytes and send it back to sender's stdout
    #sys.stdout.write(response.encode('utf-8') + b'\n')  # Write response as bytes
    sys.stdout.buffer.write(response)  # Write response as bytes
    sys.stdout.flush()  # Ensure the response is flushed

    #return pks, tkems, session_id
    


def process_data_client_retrieval():

   # Read the message from stdin (in bytes)
    try:
        byte_message = sys.stdin.buffer.read()
        #print("Received byte message:", byte_message, flush=True)
    except Exception as e:
        print(f"Error occurred: {e}", flush=True)


    if byte_message:

        try:
            challenge_server = None
            pks = None
            tkems = None
            session_id = None
            tdems = None
            #print("Payload size", len(byte_message))
            unpickle = pickle.loads(byte_message)
            serv_payld = unpickle[0]
            cl = unpickle[1]
        
            #print("Decoded message:", unpickle, flush=True)
            server_payload = pickle.loads(serv_payld) # [0] is payload & [1] is sigma
            
            server_payload1 = server_payload[0]
            server_payload1_unpickled = pickle.loads(server_payload1)
            
            challenge_server = server_payload1_unpickled[0]
            pks = server_payload1_unpickled[3]
            
            tkems = server_payload1_unpickled[4]
            
            session_id = server_payload1_unpickled[5]

            tdems = server_payload1_unpickled[6]

        except pickle.UnpicklingError as e:
            print("Error unpickling data:", e, flush=True)
        except UnboundLocalError:
            challenge_server = randbytes(16)

    sys.stdin.flush()  # flush stdin after reading in input 
    
    response = process_data_encryptor_encrypt(challenge_server, pks, tkems, session_id)
    
  
    
    # Convert the response to bytes and send it back to sender's stdout
    #sys.stdout.write(response.encode('utf-8') + b'\n')  # Write response as bytes
    sys.stdout.buffer.write(response)  # Write response as bytes
    sys.stdout.flush()  # Ensure the response is flushed

    return tkems, tdems, session_id
    

def process_data_client_smuggling():

   # Read the message from stdin (in bytes)
    try:
        byte_message = sys.stdin.buffer.read()
        #print("Received byte message:", byte_message, flush=True)
    except Exception as e:
        print(f"Error occurred: {e}", flush=True)


    if byte_message:

        try:
            challenge_server = None
            pks = None
            tkems = None
            session_id = None
            tdems = None
            #print("Payload size", len(byte_message))
            unpickle = pickle.loads(byte_message)
            serv_payld = unpickle[0]
            cl = unpickle[1]
        
            #print("Decoded message:", unpickle, flush=True)
            server_payload = pickle.loads(serv_payld) # [0] is payload & [1] is sigma
            
            server_payload1 = server_payload[0]
            server_payload1_unpickled = pickle.loads(server_payload1)
            
            challenge_server = server_payload1_unpickled[0]
            pks = server_payload1_unpickled[3]
            
            tkems = server_payload1_unpickled[4]
            
            session_id = server_payload1_unpickled[5]

            tdems = server_payload1_unpickled[6]
           
        except pickle.UnpicklingError as e:
            print("Error unpickling data:", e, flush=True)
        except UnboundLocalError:
            challenge_server = randbytes(16)

    sys.stdin.flush()  # flush stdin after reading in input 
   
    response = process_data_encryptor_smuggle(challenge_server, pks, tkems, tdems, session_id)

    
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



def encrypt_csal(sid, publicKeys=[], session=[]):

    kems = []
    dems = []
    sign = []
    secrK = helpers.fetch_value_by_primary_key('encryptor2.db', 'encryptor2', 'secretKeys', 'sid', sid)
    pk_own = helpers.fetch_value_by_primary_key('encryptor2.db', 'encryptor2', 'publicKeys', 'sid', sid)
   
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,  # PKCS#8 or TraditionalOpenSSL (PKCS#1)
    encryption_algorithm=serialization.NoEncryption()  # Or provide a password-based encryption
    )
    

    public_key = private_key.public_key()
    
    pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    #format=serialization.PublicFormat.OpenSSH
    )

    enc_suite = generate_suite()
    serial = getSerial()

    #symmK = helpers.fetch_data('encryptor2.db', 'encryptor2', 'symmetricKeys')
    symmK = helpers.fetch_value_by_primary_key('encryptor2.db', 'encryptor2', 'symmetricKeys', 'sid', sid)
    token = Fernet(symmK)
    C_dem = token.encrypt(serial)
    signature_dem = private_key.sign(
        C_dem,
        padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
                 ),
         hashes.SHA256()
    )

    dems.append(C_dem)
    sign.append(signature_dem)
    
   

    if len(publicKeys) == 0 and len(session)== 0: #first csal login
        # print("This is the first CSAL login!")
        fetch1 = helpers.fetch_data('encryptor2.db', 'encryptor2', 'publicKeys')
        #fetch_sid = helpers.fetch_data('encryptor2.db', 'encryptor2', 'sid')
        public = enc_suite.kem.deserialize_public_key(fetch1[0])
        encap, sender = enc_suite.create_sender_context(public)
        helpers.update_row('encryptor2.db', 'encryptor2', 'sid', sid, {"encapKeys":encap, "signingKeys":pem_private_key})
    
        C_kem = sender.seal(symmK)
        signature_kem = private_key.sign(
        C_kem,
        padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
                 ),
         hashes.SHA256()
          )
        kems.append(C_kem)
        sign.append(signature_kem)
        


    if len(publicKeys)>0 and len(session)>0:
        size_of_keys = len(publicKeys)
        for i in range(size_of_keys):
            pk = enc_suite.kem.deserialize_public_key(publicKeys[i])
            encap, sender = enc_suite.create_sender_context(pk)
            helpers.insert_row('encryptor2.db', 'encryptor2', ['sid', 'user', 'relyingParty', 'publicKeys', 'encapKeys', 'secretKeys', 'symmetricKeys', 'signingKeys'], (sid, 'Bob', 'facebook.com', publicKeys[i], encap, secrK, symmK, pem_private_key))
            C_kem = sender.seal(symmK) #60 bytes 
            #C_kem = sender.seal(row[6])
            signature_kems = private_key.sign(
            C_kem,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                    ),
            hashes.SHA256()
             )
            sign.append(signature_kems)

            kems.append(C_kem)
        #session should encrypt to its own public key
        pk_own_serial = enc_suite.kem.deserialize_public_key(pk_own)
        encap_own, sender1 = enc_suite.create_sender_context(pk_own_serial)
        Ckem_own = sender1.seal(symmK)
        helpers.update_row('encryptor2.db', 'encryptor2', 'sid', sid, {"encapKeys":encap_own, "signingKeys":pem_private_key})
        sign_own = private_key.sign(
            Ckem_own,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                    ),
            hashes.SHA256()
             )
        kems.append(Ckem_own)
        sign.append(sign_own)
    #cl = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Edg/120.0.100.0"}
    #serial = serial + pickle.dumps(cl)
    return kems, dems, sign, pem


def decrypt_csal(kms=[], dms=[], sess=[]):

    log = []
    kem_old = []
    dec_suite = generate_suite()
    try:
        number_keys = len(sess)
    except:
        pass
    
    
    for i in range(number_keys):
        Kems = pickle.loads(kms[i])
        symK = helpers.fetch_value_by_primary_key('encryptor2.db', 'encryptor2', 'symmetricKeys', 'sid', sess[i])
        secretK = helpers.fetch_value_by_primary_key('encryptor2.db', 'encryptor2', 'secretKeys', 'sid', sess[i])
        encp = helpers.fetch_value_by_primary_key('encryptor2.db', 'encryptor2', 'encapKeys', 'sid', sess[i])
        all_rows = helpers.fetch_rows_as_list('encryptor2.db', 'encryptor2', 'sid', sess[i])
        #if len(Kems) > 1:
        sizee = 0
        for j in range(len(all_rows)):
            for k in range(len(Kems)):
                #token = Fernet(all_rows[j][6])
                sk = dec_suite.kem.deserialize_private_key(all_rows[j][5])
                recipient = dec_suite.create_recipient_context(all_rows[j][4], sk)
                try:
                    ptx_kem = recipient.open(Kems[k])
                    token = Fernet(ptx_kem)
                    ptx_dem = token.decrypt(dms[i])
                    sizee += len(ptx_dem)
                    log.append(ptx_dem)
                    kem_old.append(ptx_kem)
                except:
                    pass
                    # print("Not decrypted")
                

                #log.append(ptx_dem)
    print(sizee)

    return log, kem_old


def decrypt_csal_smuggling(sid_curr, kms=[], sess=[]):

    kem_old = []

    dec_suite = generate_suite()
    number_keys = len(sess)
    # print("Here, is the decrypt func running?")
    for i in range(number_keys):
        #encap_key_fetch = helpers.fetch_row_by_primary_key('encryptor2.db', 'encryptor2', 'sid', sess[i])
        #encap_key = encap_key_fetch[4]
        #sk_decrypt = encap_key_fetch[5]
        symmK = helpers.fetch_entry_by_primary_key('encryptor2.db', 'encryptor2', 'sid', 'symmetricKeys', sess[i])
        token = Fernet(symmK)
        sk_decrypt = helpers.fetch_entry_by_primary_key('encryptor2.db', 'encryptor2', 'sid', 'secretKeys', sess[i])
        sk = dec_suite.kem.deserialize_private_key(sk_decrypt)
        encap_keys = helpers.fetch_entry_by_primary_key('encryptor2.db', 'encryptor2', 'sid', 'encapKeys', sess[i])
        values_list = encap_keys.split(b",")
        if len(values_list > 1):
            size_of_encap = len(values_list)
            for j in range(size_of_encap):
                recipient = dec_suite.create_recipient_context(values_list[j], sk)
                ptx_kem = recipient.open(kms[i][j])
                kem_old.append(ptx_kem)
        #ptx_dem = token.decrypt(dms[i])
    
   
    curr_k = helpers.fetch_entry_by_primary_key('encryptor2.db', 'encryptor2', 'sid', 'symmetricKeys', sid_curr)
    f = Fernet(curr_k) 
    kem_old_bytes = pickle.dumps(kem_old)
    C_old = f.encrypt(kem_old_bytes) 

    return C_old



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
    
    return signature, pem  


# Function to generate digital signatures with key sk
def generateSignature_ciphertexts(sk, c): 

    signature = sk.sign(
        c,
        padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
                 ),
         hashes.SHA256()
    )
    

    return signature 

def generate_signature(blob):

    cert, private_key = server2.generate_random_certificate()
    

    signature = private_key.sign(
        blob,
        padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
                 ),
         hashes.SHA256()
    )


    return signature


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

def run_login_no_smuggle():
    create_db_and_table('encryptor2.db')
    process_data_client_login()
   


def run_login_smuggle():
    create_db_and_table('encryptor2.db')
    process_data_client_smuggling()


def run_history_experiments():
    create_db_and_table('encryptor2.db')
    #insert_row_encryptor('encryptor2.db', 'encryptor2')
    kem, dem, sess = process_data_client_retrieval()
    lg, oldd = decrypt_csal(kem, dem, sess)
    size_of_log = len(lg)
    for i in range(size_of_log):
        print("Entry ", i, ":", lg[i])
        print(len(lg[i]))

          
    




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Select experiment to run')
    parser.add_argument('--experiment','-e', type=str, required=True, help="Experiment to run.")
    #parser.add_argument('--sessid','-s', type=int, nargs=1)

    args = parser.parse_args()

    if args.experiment == "lns":
        run_login_no_smuggle()
    elif args.experiment == "ls":
        run_login_smuggle()
    elif args.experiment == "h":
        run_history_experiments()
   


