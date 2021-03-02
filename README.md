# oracle_12_open_cl_sniffer_and_decode

Detect and decode oracle 12+ keys sent over the net. OPEN CL external libraries used and modified (MIT License)

First execute the sniffer and serverup
then execute ora12_50.py (online help)

Rate is about 100000 passwords in 1 minute with Geforce FX 1650 Super
OPENCL hashing  could be optimized, it could be run in a unique kernel. A lot of work required

**File sniffer.py** 
(run with admin permissions)

    Listen for communications with the Database server
    Reads the user handshake keys / password and sends them to the remote server

**File serverup.py and  ora_12.py**

    Listen for key from the sniffer
    When they arrive, serverup saves a json file with them
    ora_12 reads the json file and decrypts the keys
