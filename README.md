# Encrypted Access Logging for Online Accounts: Device Attributions without Device Tracking

This implementation accompanies our paper "Encrypted Access Logging for Online Accounts: Device Attributions without Device Tracking".

This is a proof-of-concept and should not be used for production.

## Setup
TODO

## Running experiments
We support running measurements for:
- Login without smuggling 

and iterations between 1 and 100.


For `n` iterations on the `login-no-smuggle` experiment, run 
```
python3 simulator.py -e login-no-smuggle -i n
```
The measured outputs are shown in the server window.