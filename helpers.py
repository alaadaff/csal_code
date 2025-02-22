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

def fetch_data_order(db_name, table_name, column_name, order_column):
    # Connect to the SQLite database
    conn = sqlite3.connect(db_name)
    
    # Create a cursor object to interact with the database
    cursor = conn.cursor()

    # SELECT data ordered by the specified column (default ROWID)
    query = f"SELECT {column_name} FROM {table_name} ORDER BY {order_column}"
    cursor.execute(query)

    # Fetch all rows from the result of the query
    rows = cursor.fetchall()

    # Extract and store the contents of the column
    column_data = [row[0] for row in rows]

    # Close the connection
    conn.close()

    return column_data



def fetch_row_by_primary_key(db_path, table_name, primary_key_column, key_value):
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create SQL query using parameterized query to prevent SQL injection
        query = f"SELECT * FROM {table_name} WHERE {primary_key_column} = ?"
        
        # Execute the query with the key value
        cursor.execute(query, (key_value,))
        
        # Fetch the result
        row = cursor.fetchone()  # Use fetchall() to get all matching rows

        # Close connection
        conn.close()

        if row:
            return list(row) #convert row from tuple to list 
        else:
            print(f"No record found with {primary_key_column} = {key_value}")
            return None

    except sqlite3.Error as e:
        print("SQLite error:", e)
        return None

def fetch_entry_by_primary_key(db_path, table_name, primary_key_column, col_name, key_value):
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create SQL query using parameterized query to prevent SQL injection
        query = f"SELECT {col_name} FROM {table_name} WHERE {primary_key_column} = ?"
        
        # Execute the query with the key value
        cursor.execute(query, (key_value,))
        
        # Fetch the result
        entry = cursor.fetchone()  # Use fetchall() to get all matching rows

        # Close connection
        conn.close()

        if entry:
            return list(entry) #convert row from tuple to list 
        else:
            print(f"No record found with {primary_key_column} = {key_value}")
            return None

    except sqlite3.Error as e:
        print("SQLite error:", e)
        return None

def update_row(db_path, table_name, primary_key_column, key_value, update_data):
    """
    Updates a row in the given SQLite database table where the primary key matches.

    Args:
        db_path (str): Path to the SQLite database file.
        table_name (str): Name of the table to update.
        primary_key_column (str): The primary key column name.
        key_value (any): The value of the primary key for the row to update.
        update_data (dict): A dictionary with column names as keys and new values as values.

    Returns:
        bool: True if the row was updated successfully, False otherwise.
    """
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Construct the SQL query dynamically
        set_clause = ', '.join([f"{column} = ?" for column in update_data.keys()])
        values = list(update_data.values())
        values.append(key_value)

        query = f"UPDATE {table_name} SET {set_clause} WHERE {primary_key_column} = ?"

        # Execute the update statement
        cursor.execute(query, values)
        conn.commit()

        # Check if the update was successful
        if cursor.rowcount == 0:
            #print(f"No record found with {primary_key_column} = {key_value}")
            return False
        else:
            #print(f"Record updated successfully where {primary_key_column} = {key_value}")
            return True

    except sqlite3.Error as e:
        print("SQLite error:", e)
        return False

    finally:
        conn.close()


import sqlite3

def append_value_as_blob(db_path, table_name, column_name, append_value, pk_column, pk_value):
    """
    Appends a value to an existing BLOB column in SQLite using a binary delimiter.

    Args:
        db_path (str): Path to the SQLite database file.
        table_name (str): Table to update.
        column_name (str): Column to append value to.
        append_value (bytes): Value to append as bytes.
        pk_column (str): Primary key column name.
        pk_value (any): The primary key value to match.

    Returns:
        bool: True if successful, False otherwise.
    """

    # Define a unique binary delimiter
    delimiter = b'\x00\xff\x00'  # Use an unlikely sequence for splitting later

    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # SQL query to append value with a binary delimiter if the column is not empty
        query = f"""
        UPDATE {table_name}
        SET {column_name} = 
            CASE 
                WHEN {column_name} IS NULL OR LENGTH({column_name}) = 0 
                THEN ? 
                ELSE {column_name} || ? || ? 
            END
        WHERE {pk_column} = ?;
        """

        # Execute the query with the binary delimiter
        cursor.execute(query, (append_value, delimiter, append_value, pk_value))
        conn.commit()

        # Check if any row was updated
        if cursor.rowcount > 0:
            #print(f"Successfully updated row with {pk_column} = {pk_value}.")
            return True
        else:
            print(f"No record found with {pk_column} = {pk_value}.")
            return False

    except sqlite3.Error as e:
        print("SQLite error:", e)
        return False

    finally:
        conn.close()


def fetch_value_by_primary_key(db_path, table_name, target_column, primary_key_column, key_value):
    """
    Fetches a specific value from a column by referencing the primary key column and value.

    Args:
        db_path (str): Path to the SQLite database file.
        table_name (str): Name of the table to fetch data from.
        target_column (str): Column from which to fetch the value.
        primary_key_column (str): The primary key column to filter the record.
        key_value (any): The value of the primary key to match.

    Returns:
        The value of the target column if found, otherwise None.
    """
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Prepare SQL query with placeholders to prevent SQL injection
        query = f"SELECT {target_column} FROM {table_name} WHERE {primary_key_column} = ?"

        # Execute the query with the primary key value as parameter
        cursor.execute(query, (key_value,))
        
        # Fetch the result (single value)
        row = cursor.fetchone()

        # Close the connection
        conn.close()

        # Return the result if found
        if row:
            return row[0]  # Return the specific column value
        else:
            print(f"No record found with {primary_key_column} = {key_value}")
            return None

    except sqlite3.Error as e:
        print("SQLite error:", e)
        return None


def insert_row(db_path, table_name, column_names, values):
    """
    Inserts a full row into the SQLite database.

    Args:
        db_path (str): Path to the SQLite database file.
        table_name (str): Name of the table to insert data into.
        column_names (list): List of column names to be inserted.
        values (tuple): Corresponding values for each column.

    Returns:
        bool: True if insertion is successful, False otherwise.
    """
    try:
        # Connect to SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Construct SQL query dynamically
        placeholders = ', '.join(['?' for _ in values])  # Create placeholders (?, ?, ?)
        columns = ', '.join(column_names)  # Format column names
        query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"

        # Execute the query
        cursor.execute(query, values)

        # Commit changes
        conn.commit()
        conn.close()

        #print("Row inserted successfully.")
        return True

    except sqlite3.Error as e:
        print("SQLite error:", e)
        return False


def fetch_rows_as_list(db_path, table_name, column_name, column_value):
    """
    Retrieves all rows from a database table where the specified column matches a given value.

    Args:
        db_path (str): Path to the SQLite database file.
        table_name (str): Name of the table.
        column_name (str): Column to filter by.
        column_value (any): Value to search for.

    Returns:
        list: A list of lists representing the retrieved rows.
    """
    try:
        # Connect to SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # SQL query to select rows where the column matches the specified value
        query = f"SELECT * FROM {table_name} WHERE {column_name} = ?"

        # Execute the query with the provided value
        cursor.execute(query, (column_value,))
        
        # Fetch all matching rows and convert tuples to lists
        rows = cursor.fetchall()
        row_list = [list(row) for row in rows]

        # Close the connection
        conn.close()

        return row_list

    except sqlite3.Error as e:
        print("SQLite error:", e)
        return []


