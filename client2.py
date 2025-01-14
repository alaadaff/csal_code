import socket
import subprocess
import sys
import simulator
from subprocess import Popen, PIPE
import time
import server2
import pickle


def forward_to_subprocess(serv_bytes):

    #serv_params = server2.server_params()
    #serv_bytes = pickle.dumps(serv_params)

    # Start the subprocess (encryptor2.py)
    process = subprocess.Popen(
        ['python3', 'encryptor2.py'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False  # Handle data as bytes, not strings
    )

    # Send a byte message to receiver.py
    #message = b'Hello from sender.py!'  # Send the message as bytes
    #print(f"Sending: {message.decode('utf-8')}")  # Optionally print the message in a human-readable form

    # Use communicate() to send and receive data
    stdout, stderr = process.communicate(input=serv_bytes)  # Automatically flushes stdin and reads stdout

    """
    # Print the received response (stdout)
    if stdout:
        #print(f"Received: {stdout.decode('utf-8')}")
        print("Received from encryptor")
        print(stdout)
        print(type(stdout))
        #print(f"Received: {stdout}")
    # Print any error messages (if any)
    """
    if stderr:
        print(f"Error: {stderr.decode('utf-8')}")

    return stdout

"""

def forward_to_subprocess():

    
    process = subprocess.Popen(
    ['python3', 'encryptor2.py'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    #bufsize=1,  # Line-buffered for better interaction
    text=True    # Enable text mode for easier string handling
    )

    # Give the receiver some time to start
    time.sleep(1)

    # Send a byte message to receiver.py
    message = "Hello from sender.py!"
    print(f"Sending: {message}")

    # Write message to stdin (which receiver.py reads)
    process.stdin.write(message)  # We add a newline for proper line handling
    process.stdin.flush()
    print("Flushed stdin")

    # Read response from stdout (which receiver.py writes)
    response = process.stdout.read()
    print(f"Received: {response}")
    #print(f"Received: {response.strip()}")
    #print(response.decode('utf-8'))

    error_message = process.stderr.read()
    if error_message:
        print(f"Error: {error_message.decode('utf-8')}")

    # Close the process
    process.stdin.close()
    process.stdout.close()
    process.stderr.close()

    process.wait()

"""   



def start_client():

    serv_params = server2.server_params()
    serv_bytes = pickle.dumps(serv_params)

    # Set up the client
    
    i = 0

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))  # Connect to the server
    
    try:
        
        while True and i<1:

            # Receive data from the server
            data = client_socket.recv(1024)
            #cl = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Edg/120.0.100.0"}
            #encryptor_data = data + (pickle.dumps(cl))
            #print(type(encryptor_data))
            #print(len(encryptor_data))
            if data:
                #print(f"Received from server: {data.decode()}")
                #print("Received from server: ", data)
                #message = "lalaland"
                print(len(data))
                message = forward_to_subprocess(data)
                
                time.sleep(1)
                client_socket.sendall(message)
                print("Login completed")
                #break
            i+=1
            
                # Send data to the server
                #message = input("Enter message to send to server: ")
                

    except KeyboardInterrupt:
        print("\nClient shutting down.")
    finally:
        client_socket.close()

   

if __name__ == '__main__':

    start_client()
    
    #simulator.run_in_terminal('python3 encryptor2.py')
    
    #serv_params = server2.server_params()
    #serv_bytes = pickle.dumps(serv_params)
    #print(serv_bytes)
    #message = b'Hello from sender.py!'
    
    #forward_to_subprocess()
    #print(res)
    #print(type(res))
    
    #print(resp)

    #print(serv_bytes)
    #print(pickle.loads(serv_bytes))



  