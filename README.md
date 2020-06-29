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



### Dependencies
`Pycryptodome` needs to be installed. If `Pycrypto` is intalled you need to uninstall it and install `Pycryptodome` otherwise you will get errors.
All other libraries used are included by default with python.

### Security
This uses the signal protocol for end to end encryption. For group end to end encrypted messaging _**Sender Keys**_ are used to avoid encrypting the same message for each user. 

<img src="https://i0.wp.com/blog.trailofbits.com/wp-content/uploads/2019/08/image2-1.png?resize=690%2C638&ssl=1" width="300">

Note that the sender keys however have to be shared with each user without the server learning about them. This is done by a pairwise **Diffie-Hellman Key exchange**.

<img src="http://blog.trendmicro.com/trendlabs-security-intelligence/files/2015/09/anglerek_dh_01.jpg" width="500">

This step is done only on intialization if users and is <img src="https://render.githubusercontent.com/render/math?math=O(n^{2})"> where n is number of users.

#### The DFKE and Sender Key exchange is done as follows: 
- When intialised the server searches for a large 2048 digit long random prime `p` which is shared over all users the base `g` used is fixed as `2`(same level as security)
- When a new user is created a random integer in `[1,p)` `a` is chosen as the private key and <img src="https://render.githubusercontent.com/render/math?math=g^{a} mod p"> is taken to be the public key which is sent to the server.
- Each user calculates its **shared secret Diffie-Hellman key** with every other user <img src="https://render.githubusercontent.com/render/math?math=g^{ab}">
- The shared secret key between each user is passed through a Key Derivation Function(PBKDF2) to generate the actual secret key for the encrypted channel
- Now each user has a pairwise secret channel with each other user.
- Note : These secret pairwise channels if used directly for messaging would require each user to encrypt each message `n-1` times for each other user and cause a lot of overhead, instead we use sender keys and rely on _server side fan out_ to send the message to each user.
- Now we generate a unique sender key for each user and use the pairwise encrypted channels to communicate the key to each other user

Note : On addition of user we only need to establish the new user's sender key by having a DFKE with each other user. All other sender keys remain intact.
Note : On deletion of user we need to reinitialize all keys to prevent eavesdropping by deleted user, this is an expensive operation as it is <img src="https://render.githubusercontent.com/render/math?math=O(n^{2})">

This can be improved by using **Asynchronous Ratcheting Trees** (Todo) which need only logarithmic key changes on addition/deletion of user.

<img src="https://i2.wp.com/blog.trailofbits.com/wp-content/uploads/2019/08/post_remove_tree.png?resize=690%2C466&ssl=1" width="500">

Now that sender keys are established we can have communication



### Communication
 Socket headers etc..
 
### Misc 
pickle multithreading etc
### Demo
Run server.py to setup server and client.py from multiple terminals to setup each client
The key exchange and encryption protocols are implemented in utils.py


Since each user runs on a different thread the number of users is limited by the number of simultaneous threads(around 40) if run on same device(for testing)

Running on different devices would allow lot more clients(not tested). User addition and deletion scales quadratically with number of users. However each message has to be encrypted only once due to usage of sender keys

### Todo

(some functionality like proper asynchronicity are yet to be implemented)
