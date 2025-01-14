from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Name, NameAttribute, CertificateBuilder
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import datetime
import random
import socket
import sqlite3
import argparse
import simulator
from random import randbytes
import secrets
import base64
import string
import datetime
import pickle
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import CertificateBuilder, Name, NameAttribute
from cryptography.x509.oid import NameOID
import cryptography.x509
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

#function to create the server db if does not exist
def create_db_and_table(db_name):
    # Connect to the SQLite database (it will be created if it doesn't exist)
    conn = sqlite3.connect(db_name)

    # Create a cursor object to interact with the database
    cursor = conn.cursor()

    # Create a table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        uid INTEGER PRIMARY KEY,
        user TEXT,
        sid TEXT,
        publicKeys BLOB,
        CKEMs BLOB,
        CDEMs BLOB           

    )
    ''')

    #Try insert into db
    #cursor.execute("INSERT INTO server (publicKeys) VALUES (?)", ('\x04e\xed\xa5\xa1%w\xc2\xba\xe8)C\x7f\xe38p\x1a',))

    # Commit the changes and close the connection
    conn.commit()
    conn.close()


 #returns list of all rows, and each column_data[0] is the value of first row in string 
def fetch_data(db_name, table_name, column_name):
    # Connect to the SQLite database
    conn = sqlite3.connect(db_name)
    
    # Create a cursor object to interact with the database
    cursor = conn.cursor()

    #SELECT data from the specified column in the given table
    query = f"SELECT {column_name} FROM {table_name}"  
    cursor.execute(query)

    # Fetch all rows from the result of the query
    rows = cursor.fetchall()

    # Extract and store the contents of the column
    column_data = [row[0] for row in rows]  # Since each row is a tuple, the data is in row[0]
    #column_data = " ".join(column_data) 
    # Print the contents of the column
    #print(column_data)

    # Close the connection
    conn.close()

    return column_data

def insert_row_server(db_name, table_name, pickled_data):
    """
    Insert a row into the specified SQLite table with generated sid and data.
    
    Args:
        db_name (str): The name of the SQLite database file.
        table_name (str): The name of the table into which data is being inserted.

    """
    userid = random.randint(1, 9999)
    data = pickle.loads(pickled_data)
    user = "Alice"
    sid = data[0]
    publicK = data[1]
    ckem = data[2]
    cdem = data[3]
    try:
        
        # Connect to the SQLite database
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        # Prepare the SQL query with placeholders for variables
        sql = f"INSERT INTO {table_name} (uid, user, sid, publicKeys, CKEMs, CDEMs) VALUES (?, ?, ?, ?, ?, ?)"
        
        # Execute the query, passing the values as a tuple
        cursor.execute(sql, (userid, user, sid, publicK, ckem, cdem))
        
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


#function to create random RP certs and signature 
def generate_random_string(length=10):
    """Generate a random string of fixed length."""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_random_certificate():
    """
    Generate a random self-signed X.509 certificate and private key.
    Returns the certificate and private key in PEM format.
    """
    # Generate a random RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate the public key from the private key
    public_key = private_key.public_key()

    # Randomly generate subject name details
    country = generate_random_string(2)  # 2-character country code
    state = generate_random_string(8)    # Random state/province name
    city = generate_random_string(8)     # Random city name
    organization = generate_random_string(12)  # Random organization name
    common_name = generate_random_string(15)   # Random domain name for common name (CN)

    # Create the subject name with random values
    subject_name = Name([
        NameAttribute(NameOID.COUNTRY_NAME, country),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        NameAttribute(NameOID.LOCALITY_NAME, city),
        NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Use the subject name for both the subject and the issuer (self-signed)
    issuer_name = subject_name

    # Set the validity period (valid for 365 days)
    not_valid_before = datetime.datetime.utcnow()
    not_valid_after = not_valid_before + datetime.timedelta(days=365)

    # Generate a random serial number
    serial_number = random.randint(1000, 9999)

    # Generate the certificate
    certificate = CertificateBuilder().subject_name(subject_name).issuer_name(issuer_name).public_key(public_key
    ).serial_number(serial_number).not_valid_before(not_valid_before).not_valid_after(not_valid_after
    ).add_extension(
        cryptography.x509.SubjectAlternativeName([cryptography.x509.DNSName(common_name)]), critical=False
    ).sign(private_key, hashes.SHA256())

    # Serialize the certificate to PEM format
    cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)

    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


    # Return the PEM-encoded certificate and private key
    #To return private key, return private_key_pem.decode('utf-8'), cert_pem.decode('utf-8'), signature
    #return cert_pem.decode('utf-8'), private_key
    return cert_pem, private_key

#1647 bytes

def server_params():

    challenge = str(randbytes(16))
    cookie = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
    #PK = fetch_data('server.db', 'users', 'publicKeys') #pulled from db
    #tKEM = fetch_data('server.db', 'users', 'ciphertexts') #pulled from db
    keyParams = [{"key_params": "public-key", "alg": -7}]
    publicKeys = fetch_data('server.db', 'users', 'publicKeys')
    #tKEM = fetch_data('server.db', 'users', 'CKEMs')
    #server_payload = [challenge, cookie, PK, tKEM, keyParams]
    server_payload = [challenge, cookie, keyParams, publicKeys]
    print(server_payload)

    return server_payload


def parse_data(pickled_data):

    data = pickle.loads(pickled_data)


    pass


def generate_signature():

    cert, private_key = generate_random_certificate()
    blob = server_params()
    blob.append(cert)
    blob = pickle.dumps(blob)
    

    signature = private_key.sign(
        blob,
        padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
                 ),
         hashes.SHA256()
    )

    
    #blob_bytes = bytearray()
    #blob_bytes.extend(signature)
    #blob_bytes.extend(blob)
    

    return blob, signature






#function to start the server
def start_server():
    # Set up the server
    create_db_and_table('server.db')

    #create params for a new session [N, certRP, sigma, cookie, params, cookie temp]
    

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))  # Binding to localhost on port 12345
    server_socket.listen(4)  # Listen for one client connection

    print("Server is listening for incoming connections...")

    
    # Accept incoming client connection
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")
    
    

    try:
        while True:
    
            # Receive data from the client
            #data = client_socket.recv(1024)
            #if not data:
            #    break  # If no data, exit the loop (client disconnected)
            #print(f"Received from client: {data.decode()}")

            # Send data back to the client
            #else:
            #message = str(fetch_data('server.db', 'users', 'publicKeys'))
                #message = input("Enter message to send to client: ")
            #if message:    
            #client_socket.sendall(message.encode())
            servPayload, sigma = generate_signature()
            all_payload = servPayload + sigma
            client_socket.sendall(all_payload)
            print(len(all_payload))
            data = client_socket.recv(1024)
            if data:
                #print(f"Received from client: {data.decode()}")
                #print(data)
                #print(len(data))
                insert_row_server('server.db', 'users', data)
                
                #break
                #break
            
            
            
            #else:
            #    break
            
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    finally:
        client_socket.close()
        server_socket.close()


def main():
    #parser = argparse.ArgumentParser()
    #parser.add_argument('message', type=str, help='Message to send to the client')
    #args = parser.parse_args()
   
   
   
    
    start_server()

  
    #sqlite3.connect('server.db').execute("INSERT INTO server (publicKeys) VALUES (?)", ('\x04e\xed\xa5\xa1%w\xc2\xba\xe8)C\x7f\xe38p\x1a',)).connection.commit()


if __name__ == '__main__':
   
   main()

    #start_server()
    #create_db_and_table('server.db')

