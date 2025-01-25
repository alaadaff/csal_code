# Encrypted Access Logging for Online Accounts: Device Attributions without Device Tracking

This implementation accompanies our paper "Encrypted Access Logging for Online Accounts: Device Attributions without Device Tracking".

This is a proof-of-concept and should not be used for production. We used a MacBook Pro device for our implementation and we are using macOS's system profiler to 
retrieve the device's serial number. This routine will vary among OSes and thus we recommend running the program in a macOS environment.  

We're using TCP sockets for client server communication and thus we're binding to a port. Running the program multiple times repeatedly might present an error that 
the port is busy and "address is already used". We recommed killing the processes running using: lsof -i :12345 and kill -9 pid
## Setup
TODO

## Running experiments
We support running measurements for:
- Login without smuggling 

and iterations between 1 and 20.


For `n` iterations on the `login-no-smuggle` experiment, run 
```
python3 simulator.py -e login-no-smuggle -i n
```
The measured outputs are shown in the server window.