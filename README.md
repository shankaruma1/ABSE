# ABSE
**About** 

This project is the implementation of the following paper. (I will cite the paper once it is accepted)

It involves execution of different algorithms of the above paper. We used Windows laptop with an Intel Core 7200U processor clocked at 2.5 GHz and 8 GB of RAM. In addition, the pairing-based cryptography (PBC) library and Python 3.5 programming language were also used to run simulations.

**algo.py** file contains all the algorithm implementations of the above paper. 

List of algorithms are as follows:

setup(): Algorithm to generate public parameters and master secret key

keygen(): Algorithm to generate secret key

doenc(): Algorithm for partial ecryption at data owner

edgeenc(): Algorithm for full encryption at edge node

indexgen(): Algorithm to generate encrypted index

trapgen(): algorithm to generate trapdoor

search(): Algorithm to perform search operation between index and trapdoor

edgedec(): Algorithm for partial decryption at edge node

dudec(): Algorithm for full decryption at data user

keysanitycheck(): Algorithm to check validity of secret key

trace(): Algorithm to return user id

**policy.py** file is used to generate access policy

**How to Run**

Open any python IDE (Ex.PyCharm)

Run _main.py_ file 

To experiment with different number of attributes and keywords, change them accordingly in _main.py_ file
