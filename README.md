# Hermes
**H**ashed, **E**ncrypted and **R**atched **MES**saging : An asynchronous end to end encrypted messaging socket application based on the signal protocol 

This is a group messaging application which implements the signal protocol for secure encrypted communication.

- End to End encryption ensures server learns nothing about messages and only acts as a relay
- Uses HMAC to verify ciphertext integrity and prevent ciphertext tampering
- Group messaging is end to end encrypted with each user using a unique sender key
- Sender Keys are shared on user addition using a asymmetric encrypted channel created using a Diffie-Hellman key exchange
- Key ratcheting is done after each message to ensure backward secrecy of ciphertext
- Application is asynchronous hence all users dont need to be online for key exchange
- Socket library in python is used to connect server and client

Run server.py to setup server and client.py from multiple terminals to setup each client
The key exchange and encryption protocols are implemented in utils.py


Since each user runs on a different thread the number of users is limited by the number of simultaneous threads(around 40) if run on same device(for testing)

Running on different devices would allow lot more clients(not tested). User addition and deletion scales quadratically with number of users. However each message has to be encrypted only once due to usage of sender keys

(This Repo is incomplete and under development)
(some functionality like ratcheting and asynchronicity are yet to be implemented)
