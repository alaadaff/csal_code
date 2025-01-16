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
import argparse

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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Select experiment to run')
    parser.add_argument('--experiment','-e', type=str, nargs=1,
                    help="Select which experiment to run. Select between \
                            'login-no-smuggle', 'login-all', 'action', 'reenc', and 'history'.")
    parser.add_argument('--iterations','-i', type=int, nargs=1, default=1, 
                        choices=range(1,101), help="Count of how many iterations.")

    args = parser.parse_args()

    if args.experiment[0] == "login-no-smuggle":
        run_in_terminal('python server2.py' + f' -e lns -i {args.iterations[0]}')
        time.sleep(2)
        run_in_terminal('python client2.py' + f' -e lns -i {args.iterations[0]}')
    elif args.experiment[0] == "login-all":
        run_in_terminal('python server2.py' + f' -e ls -i {args.iterations[0]}')
        time.sleep(2)
        run_in_terminal('python client2.py' + f' -e ls -i {args.iterations[0]}')
    elif args.experiment[0] == "action":
        run_in_terminal('python server2.py' + f' -e a -i {args.iterations[0]}')
        time.sleep(2)
        run_in_terminal('python client2.py' + f' -e a -i {args.iterations[0]}')
    elif args.experiment[0] == "reenc":
        run_in_terminal('python server2.py' + f' -e r -i {args.iterations[0]}')
        time.sleep(2)
        run_in_terminal('python client2.py' + f' -e r -i {args.iterations[0]}')
    elif args.experiment[0] == "history":
        run_in_terminal('python server2.py' + f' -e h -i {args.iterations[0]}')
        time.sleep(2)
        run_in_terminal('python client2.py' + f' -e h -i {args.iterations[0]}')
    else:
        print(f"Option {args.experiment[0]} is not valid. \
              Valid options are: 'login-no-smuggle', 'login-all', 'action', 'reenc', and 'history' (no quotation signs).")
    





    # run_in_terminal('python server2.py')
    # time.sleep(2)
    # run_in_terminal('python client2.py')


    #test1 = fetch_data('server.db', 'users', 'publicKeys')
    #test1 = str(test1)
    #print(type(test1))
    #var = "bless"
    
#Define the commands for each Python file to be executed
#     python_files = [
#         'python server2.py ',
#         'python client2.py'
#         #'python encryptor_hardware.py'
#     ]

# #Run each Python script in a new terminal window
#     for command in python_files:
#         run_in_terminal(command)
#         time.sleep(2)


    
    
    

    