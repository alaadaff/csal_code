import argparse
import pickle
import socket
import subprocess
import sys
import time
from subprocess import PIPE, Popen


class CSALClient():
    def __init__(self):
        self.client_socket = None
        #self.sid = 0

    def start_client(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('localhost', 12345))  # Connect to the server

    def client_run_login(self, smuggle=False):
        loginf = 'lns'
        if smuggle:
            loginf = 'ls'
        i = 0    
        try:
            while True and i<4:
                
                # Receive data from the server
                data = self.client_socket.recv(2048)
                time.sleep(1)
                # print(data)
                # print(len(data))
                #cl = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Edg/120.0.100.0"}
                #encryptor_data = data + (pickle.dumps(cl))
                #print(type(encryptor_data))
                #print(len(encryptor_data))
                if data:
                    #message = forward_to_subprocess(data, loginf)
                    message = b'helllooo'
                    time.sleep(1)
                    self.client_socket.sendall(message)
                    print(message)
                    print("Login completed")
                    #self.sid += 1 
                    #break
                
                    # Send data to the server
                    #message = input("Enter message to send to server: ")
                i+=1
        except KeyboardInterrupt:
            print("\nClient shutting down.")
        finally:
            self.client_socket.close()

def forward_to_subprocess(serv_bytes, action):

    #serv_params = server2.server_params()
    #serv_bytes = pickle.dumps(serv_params)

    # Start the subprocess (encryptor2.py)
    process = subprocess.Popen(
        ['python3', 'encryptor2.py', '-e', action],
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

def run_login_experiments(cl, iter):
    print(1)
    pass

def run_login_experiments_no_smuggle(cl, iter):
    try:
        cl.start_client()
        #for _ in range(iter):
        cl.client_run_login(False)
    except:
        raise Exception("Error")
    

def run_reenc_experiments(cl, iter):
    print(3)
    pass

def run_action_experiments(cl, iter):
    print(4)
    pass

def run_history_experiments(cl, iter):
    print(5)
    pass 

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Select experiment to run')
    parser.add_argument('--experiment','-e', type=str, required=True, help="Experiment to run.")
    parser.add_argument('--iterations','-i', type=int, default=1, 
                        choices=range(1,101), help="Count of how many iterations.")
   
    args = parser.parse_args()

    start_time = time.process_time()
    csal_cl = CSALClient()

    if args.experiment == "lns":
        run_login_experiments_no_smuggle(csal_cl, args.iterations)
    elif args.experiment == "ls":
        run_login_experiments(csal_cl, args.iterations)
    elif args.experiment == "a":
        run_action_experiments(csal_cl, args.iterations)
    elif args.experiment == "r":
        run_reenc_experiments(csal_cl, args.iterations)
    elif args.experiment == "h":
        run_history_experiments(csal_cl, args.iterations)

    # start_client()
    
    end_time = time.process_time()
    #simulator.run_in_terminal('python3 encryptor2.py')
    cpu_time = end_time - start_time
    print(f"CPU time used: {cpu_time} seconds")
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



  