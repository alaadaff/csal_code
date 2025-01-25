import argparse
import pickle
import socket
import subprocess
import sys
import time
from subprocess import PIPE, Popen



def forward_to_subprocess(serv_bytes, action):


    # Start the subprocess (encryptor2.py)
    process = subprocess.Popen(
        ['python3', 'encryptor2.py', '-e', action],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        #stdout=sys.stdout, #for printing to client2 terminal for debugging
        stderr=subprocess.PIPE,
        text=False  # Handle data as bytes, not strings
    )

    # Use communicate() to send and receive data
    stdout, stderr = process.communicate(input=serv_bytes)  # Automatically flushes stdin and reads stdout

    if stdout:
        print("Subprocess Output:\n", stdout)

    if stderr:
        print(f"Error: {stderr.decode('utf-8')}")

    return stdout



class CSALClient():
    def __init__(self):
        self.client_socket = None
        #self.sid = 0

    def start_client(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('localhost', 12345))  # Connect to the server

    def client_run_login(self, iter=1, smuggle=False):
        loginf = 'h'
        if smuggle:
            loginf = 'ls'
        i = 0    
        try:
            while True and i<iter:
                
                # Receive data from the server
                data = self.client_socket.recv(262144)
                cl = b'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Edg/120.0.100.0'
                data_cl = [data, cl]
                data_encryptor = pickle.dumps(data_cl)
                if data:
                    message = forward_to_subprocess(data_encryptor, loginf)
                    self.client_socket.sendall(message)
                    print("Login completed")
                    
    
                i+=1
        except KeyboardInterrupt:
            print("\nClient shutting down.")
        finally:
            self.client_socket.close()




def run_login_experiments(cl, iter):
    try:
        cl.start_client()
        #for _ in range(iter):
        cl.client_run_login(iter, False)
    except:
        raise Exception("Error")

def run_login_experiments_no_smuggle(cl, iter):
    try:
        cl.start_client()
        #for _ in range(iter):
        cl.client_run_login(iter, False)
    except:
        raise Exception("Error")
    

def run_reenc_experiments(cl, iter):
    print(3)
    pass

def run_action_experiments(cl, iter):
    print(4)
    pass

def run_history_experiments(cl, iter):
    try:
        cl.start_client()
        #for _ in range(iter):
        cl.client_run_login(iter, False)
    except:
        raise Exception("Error")


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


    end_time = time.process_time()
    #simulator.run_in_terminal('python3 encryptor2.py')
    cpu_time = end_time - start_time
    print(f"CPU time used: {cpu_time} seconds")
    



  