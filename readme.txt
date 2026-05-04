Setup
set the address inside server.py
and 
Application URL

Require Maturin, Flask, Rust

Server:
./build.sh
python3 server.py

SmartContract and test script is under server/

Verifiability components (Cut-and-choose) are under my_benchmark.rs
Use NDK to build benches and then load the binary into Android to run.

App:
See App readme.txt
