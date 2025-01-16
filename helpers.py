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
import subprocess
import uuid
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
from pyhpke import (AEADId, CipherSuite, KDFId, KEMId, KEMInterface, KEMKey,
                    KEMKeyInterface, KEMKeyPair)


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

def insert_into_single_column(db_name, table_name, column_name, values):
    """
    Inserts values into a single column of the specified table in the SQLite database.

    Parameters:
    - db_name: The name of the SQLite database file.
    - table_name: The name of the table where values will be inserted.
    - column_name: The column name into which values will be inserted.
    - values: A list or tuple of values to insert into the column.
    """
    # Connect to the SQLite database
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Prepare the SQL INSERT statement
    sql = f"INSERT INTO {table_name} ({column_name}) VALUES (?)"

    # Execute the INSERT statement for each value in the values list
    for value in values:
        cursor.execute(sql, (value,))

    # Commit the transaction and close the connection
    conn.commit()
    conn.close()

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
        
        #print(f"Value '{value}' inserted into '{table_name}' table, column '{column_name}'.")
    
    except sqlite3.Error as e:
        # Catch any SQLite errors
        print(f"SQLite Error: {e}")
    
    finally:
        # Close the database connection
        conn.close()


def delete_database(db_name):
    """
    Deletes the SQLite database file.
    
    Args:
        db_name (str): The name of the SQLite database file to be deleted.
    """
    try:
        # Check if the database file exists
        if os.path.exists(db_name):
            os.remove(db_name)  # Delete the database file
            print(f"Database '{db_name}' has been deleted.")
        else:
            print(f"Database '{db_name}' does not exist.")
    
    except Exception as e:
        print(f"Error occurred while deleting the database: {e}")        



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

    public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Return the PEM-encoded certificate and private key
    #To return private key, return private_key_pem.decode('utf-8'), cert_pem.decode('utf-8'), signature
    #return cert_pem.decode('utf-8'), private_key
    return cert_pem, private_key, public_pem        


    """
    Returns list of all rows, and each column_data[0] is the value of first row in string 
    """
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




def main():

    #cert, sk, pk = generate_random_certificate()
    #print(len(pk))
    #print(len(cert))
    connection = sqlite3.connect('server.db')

    # Create a cursor object to interact with the database
    cursor = connection.cursor()

    # SQL query to fetch all data from a table (replace 'your_table' with your actual table name)
    query = "SELECT * FROM your_table;"

    # Execute the query
    cursor.execute(query)

    # Fetch all the rows from the result of the query
    rows = cursor.fetchall()

    # Iterate over the rows and print each row
    for row in rows:
        print(row)
        print(type(row))
        print(len(row))

    # Close the cursor and connection
    cursor.close()
    connection.close()


if __name__ == '__main__':
   
    main()    

