# Encrypted Access Logging for Online Accounts: Device Attributions without Device Tracking

This implementation accompanies our paper "Encrypted Access Logging for Online Accounts: Device Attributions without Device Tracking".

This is a proof-of-concept and should not be used for production. We used a MacBook Pro device for our implementation and we are using macOS's system profiler to 
retrieve the device's serial number. This routine will vary among OSes and thus we recommend running the program in a macOS environment.  

We're using TCP sockets for client server communication and thus we're binding to a port. Running the program multiple times repeatedly might present an error that 
the port is busy and "address is already used". We recommend killing the processes running using: `lsof -i :12345` and `kill -9 pid`.

## Setup
To install the dependency packages run:
```
pip install -r requirements.txt
```

## Running experiments
We support running ent-to-end measurements for:
- Login without smuggling 
- Login with smuggling
- History retrieval

for iterations between 1 and 20. Additionally, we support size measurements for individual components, enough to analyze the payload of the remaining functions. 


For `n` iterations on an experiment `experiment_name`, run 
```
python3 simulator.py -e login-no-smuggle -i n
```
where `experiment_name` can be selected among `login-no-smuggle`, `login-all`, and `history`.
The measured outputs are shown in the server window.

For the size measurements, run
`python encryptor_entry_size.py`
and
`python algorithms_payload_size.py`