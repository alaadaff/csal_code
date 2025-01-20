import encryptor2
import server2
import sqlite3 
import random 
from random import randbytes
import sys

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
        #encap, sender = suiteEnc.create_sender_context(public)
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


#encryptor2.create_db_and_table('encryptor2.db')
#insert_row_encryptor('encryptor2.db', 'encryptor2')

sid = server2.fetch_data('encryptor2.db', 'encryptor2', 'sid')
user = server2.fetch_data('encryptor2.db', 'encryptor2', 'user')
RP = server2.fetch_data('encryptor2.db', 'encryptor2', 'relyingParty')
pk = server2.fetch_data('encryptor2.db', 'encryptor2', 'publicKeys')
encap = server2.fetch_data('encryptor2.db', 'encryptor2', 'encapKeys')
sk = server2.fetch_data('encryptor2.db', 'encryptor2', 'secretKeys')
symmk = server2.fetch_data('encryptor2.db', 'encryptor2', 'symmetricKeys')


print(len(sid[0]))
print(sys.getsizeof(user[0]))
print(sys.getsizeof(RP[0]))
print(len(pk[0]))
print(len(encap[0]))
print(len(sk[0]))
print(len(symmk[0]))

#ls -l encryptor2.db --> size of db 