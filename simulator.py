"""

This file contains code to instrument the entire protocol runs:

- Spins up three CMDs of the csal_server, csal_client, and encryptor_hardware
- Initiates TCP socket connections between server and client and a pipes connection between client and encryptor
- Provide contents to the payload transferred between server and clients


"""

import subprocess
import os
import sys
import time
import sqlite3
import server2


#fetches data from both server and encryptor dbs
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



def run_in_terminal(command):
    # Get the current working directory (VS Code project directory)
    current_dir = os.getcwd()
    """Open a new terminal window and run a Python script in the current directory."""
    if sys.platform.startswith('linux'):
        # For Linux (GNOME Terminal or any other terminal)
        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'cd {current_dir} && {command}'])
    elif sys.platform == 'darwin':  # macOS
        # For macOS (using AppleScript to open Terminal)
        script = f'''
        tell application "Terminal"
            do script "cd {current_dir} && {command}"
        end tell
        '''
        subprocess.Popen(['osascript', '-e', script])
    elif sys.platform == 'win32':  # Windows
        # For Windows, use 'start' with cmd (run in the current directory)
        subprocess.Popen(['start', 'cmd', '/K', f'cd /d {current_dir} && {command}'], shell=True)
    else:
        print("Unsupported OS")




def csal_login():
    #pending
    run_in_terminal('python server2.py')
    time.sleep(2)
    run_in_terminal('python client2.py')
    


if __name__ == '__main__':
   
    #test1 = fetch_data('server.db', 'users', 'publicKeys')
    #test1 = str(test1)
    #print(type(test1))
    #var = "bless"
    
#Define the commands for each Python file to be executed
    python_files = [
        'python server2.py ',
        'python client2.py'
        #'python encryptor_hardware.py'
    ]

#Run each Python script in a new terminal window
    for command in python_files:
        run_in_terminal(command)
        time.sleep(2)


    
    
    

    