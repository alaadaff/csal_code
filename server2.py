import argparse
import base64
import datetime
import os
import pickle
import random
import secrets
import socket
import sqlite3
import string
import sys
import time
from random import randbytes

import cryptography.x509
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import CertificateBuilder, Name, NameAttribute
from cryptography.x509.oid import NameOID

import helpers


class CSALServer():
    def __init__(self):
        self.db_name = 'server.db'
        self.certificate = None
        self.cert_sk = None
        self.server_socket = None
        self.client_socket = None

    def start_server(self):
        """ Initialize CSALServer attributes"""

        # Set up the server
        self.create_db_and_table()
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow port reuse
        self.server_socket.bind(('localhost', 12345))  # Binding to localhost on port 12345
        self.server_socket.listen(1)  # Listen for one client connection

        print("Server is listening for incoming connections...")

        
        # Accept incoming client connection
        self.client_socket, client_address = self.server_socket.accept()
        print(f"Connection established with {client_address}")

        self.certificate, self.cert_sk = generate_random_certificate()


    def create_db_and_table(self):
        """ Create the server db if does not exist """
        # Connect to the SQLite database (it will be created if it doesn't exist)
        conn = sqlite3.connect(self.db_name)

        # Create a cursor object to interact with the database
        cursor = conn.cursor()

        # Create a table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            uid INTEGER PRIMARY KEY,
            user TEXT,
            sid BLOB,
            publicKeys BLOB,
            CKEMs BLOB,
            CDEMs BLOB,
            COLD BLOB                      
        )
        ''')

        # Commit the changes and close the connection
        conn.commit()
        conn.close()

    def insert_row_server(self, table_name, pickled_data, i):
        """
        Insert a row into the specified SQLite table with generated sid and data.
        
        Args:
            
            table_name (str): The name of the table into which data is being inserted.
            pickled_data : data to add to the table in pickled format
        """
        userid = random.randint(1, 9999)
        data = pickle.loads(pickled_data)
        if len(data) == 10:
            print("here 10")
            user = "Alice"
            sid = data[0][i]
            publicK = data[1][i]
            #ckem = data[2][0]
            print(len(data[2]))
            ckem = pickle.dumps(data[2])
            cdem = data[3][0]
            cold = data[4]
        elif len(data) == 9:
            print("here 9")
            user = "Alice"
            sid = data[0][i]
            publicK = data[1][i]
            #ckem = data[2][0]
            #ckem = data[2]
            print(len(data[2]))
            ckem = pickle.dumps(data[2])
            cdem = data[3][0]
            cold = None

        try:
            
            # Connect to the SQLite database
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            # Prepare the SQL query with placeholders for variables
            sql = f"INSERT INTO {table_name} (uid, user, sid, publicKeys, CKEMs, CDEMs, COLD) VALUES (?, ?, ?, ?, ?, ?, ?)"
            
            # Execute the query, passing the values as a tuple
            cursor.execute(sql, (userid, user, sid, publicK, ckem, cdem, cold))
            
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


    def server_params_login(self):

        challenge = str(randbytes(16))
        cookie = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
        keyParams = [{"key_params": "public-key", "alg": -7}]
        publicKeys = helpers.fetch_data('server.db', 'users', 'publicKeys')
        tKEM = helpers.fetch_data('server.db', 'users', 'CKEMs')
        sessid = helpers.fetch_data('server.db', 'users', 'sid')
        tDEM = helpers.fetch_data('server.db', 'users', 'CDEMs')
        server_payload = [challenge, cookie, keyParams, publicKeys, tKEM, sessid, tDEM]
        # print(server_payload)

        return server_payload

    def server_run_login(self, tlog, log_s, log_e, smuggle=False):
        # Create params for a new session [N, cookie_tmp, params, PKs, certRP, sigma]
        t0 = time.time()
        #blob = self.server_params_login()
        #servPayload, sigma = generate_signature(self.certificate, self.cert_sk, blob)
        #all_payload = pickle.dumps([servPayload, sigma]) 
        #log_s.append(len(all_payload))
      
        try:

            #self.client_socket.sendall(all_payload)
            count=0
            while True:
                #send = b'sending...'
                try:
                    blob = self.server_params_login()
                    servPayload, sigma = generate_signature(self.certificate, self.cert_sk, blob)
                    all_payload = pickle.dumps([servPayload, sigma]) 
                    self.client_socket.sendall(all_payload)
                    time.sleep(1)
                except BrokenPipeError:
                    print("Broken pipe: Client is no longer connected. Closing socket.")
                    break
                   
                data = self.client_socket.recv(8192)
                if not data:
                    print("Client disconnected.")
                    break  # Exit loop if client disconnects
                if data:
                    dat = pickle.loads(data)
                    self.insert_row_server('users', data, count)
                    t1 = time.time()
                    log_e.append(len(data))
                    #break
                count+=1   

                tlog.append(t1-t0-1)

        except ConnectionResetError:
            print("CSAL login completed")
            #break  # Exit the loop gracefully
        except KeyboardInterrupt:
            print("\nServer shutting down.")
        finally:
            self.client_socket.close()
            self.server_socket.close()

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

def parse_data(pickled_data):

    data = pickle.loads(pickled_data)


    pass

def generate_signature(cert, sk, blob):
    if cert == None or sk == None:
        raise  Exception("No certificate or secret key")

    # blob = server_params_login()
    blob.append(cert)
    blob = pickle.dumps(blob)
    

    signature = sk.sign(
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

#def main():
    #parser = argparse.ArgumentParser()
    #parser.add_argument('message', type=str, help='Message to send to the client')
    #args = parser.parse_args()
#    srv = CSALServer() 
#    srv.start_server()
   
    """
    #start_server()
    connection = sqlite3.connect('server.db')

    # Create a cursor object to interact with the database
    cursor = connection.cursor()

    # SQL query to fetch all data from a table (replace 'your_table' with your actual table name)
    query = "SELECT * FROM users;"

    # Execute the query
    cursor.execute(query)

    # Fetch all the rows from the result of the query
    rows = cursor.fetchall()

    # Iterate over the rows and print each row
    for row in rows:
        for i in range(2, 6):
            print(row[i])
            #print(sys.getsizeof(row[i]))
            print(len(row[i]))

    # Close the cursor and connection
    cursor.close()
    connection.close()

    """
    #sqlite3.connect('server.db').execute("INSERT INTO server (publicKeys) VALUES (?)", ('\x04e\xed\xa5\xa1%w\xc2\xba\xe8)C\x7f\xe38p\x1a',)).connection.commit()

def run_login_experiments(srv, iter):
    times_log = []
    server_sizes_log = []
    encryptor_sizes_log = []
    try:
        srv.start_server()
        #for i in range(iter):
        #    print(f"Iteration {i}")
        srv.server_run_login(times_log, server_sizes_log, encryptor_sizes_log, True)
    except:
        raise Exception("Error")
    finally:
        if srv.client_socket != None:
            srv.client_socket.close()
        if srv.server_socket != None:
            srv.server_socket.close()
        #os.system(f'rm {srv.db_name}')
        #os.system(f'rm encryptor2.db')
        print(f"Size of bundle from the server to the client for 1 through {iter} sessions:\n {server_sizes_log}")
        print(f"Size of bundle from the client to the server for 1 through {iter} sessions:\n {encryptor_sizes_log}")
        print(f"Computation time at for 1 through {iter} sessions (seconds):\n {times_log}")

def run_login_experiments_no_smuggle(srv, iter):
    times_log = []
    server_sizes_log = []
    encryptor_sizes_log = []
    try:
        srv.start_server()
        #for i in range(iter):
        #    print(f"Iteration {i}")
        srv.server_run_login(times_log, server_sizes_log, encryptor_sizes_log, False)
    except:
        raise Exception("Error")
    finally:
        if srv.client_socket != None:
            srv.client_socket.close()
        if srv.server_socket != None:
            srv.server_socket.close()
        #os.system(f'rm {srv.db_name}')
        #os.system(f'rm encryptor2.db')
        print(f"Size of bundle from the server to the client for 1 through {iter} sessions:\n {server_sizes_log}")
        print(f"Size of bundle from the client to the server for 1 through {iter} sessions:\n {encryptor_sizes_log}")
        print(f"Computation time at for 1 through {iter} sessions (seconds):\n {times_log}")

def run_reenc_experiments(srv, iter):
    print(3)
    pass

def run_action_experiments(srv, iter):
    print(4)
    pass

def run_history_experiments(srv, iter):
    times_log = []
    server_sizes_log = []
    encryptor_sizes_log = []
    try:
        srv.start_server()
        #for i in range(iter):
        #    print(f"Iteration {i}")
        srv.server_run_login(times_log, server_sizes_log, encryptor_sizes_log, False)
    except:
        raise Exception("Error")
    finally:
        if srv.client_socket != None:
            srv.client_socket.close()
        if srv.server_socket != None:
            srv.server_socket.close()
        os.system(f'rm {srv.db_name}')
        os.system(f'rm encryptor2.db')
        print(f"Size of bundle from the server to the client for 1 through {iter} sessions:\n {server_sizes_log}")
        print(f"Size of bundle from the client to the server for 1 through {iter} sessions:\n {encryptor_sizes_log}")
        print(f"Computation time at for 1 through {iter} sessions (seconds):\n {times_log}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Select experiment to run')
    parser.add_argument('--experiment','-e', type=str, required=True, help="Experiment to run.")
    parser.add_argument('--iterations','-i', type=int, default=1, 
                        choices=range(1,101), help="Count of how many iterations.")
   
    args = parser.parse_args()
    # print(args)

    csal_srv = CSALServer()

    if args.experiment == "lns":
        run_login_experiments_no_smuggle(csal_srv, args.iterations)
    elif args.experiment == "ls":
        run_login_experiments(csal_srv, args.iterations)
    elif args.experiment == "a":
        run_action_experiments(csal_srv, args.iterations)
    elif args.experiment == "r":
        run_reenc_experiments(csal_srv, args.iterations)
    elif args.experiment == "h":
        run_history_experiments(csal_srv, args.iterations)
   
#    main()

    #start_server()
    #create_db_and_table('server.db')

