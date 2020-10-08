# Hermes
**H**ashed, **E**ncrypted, and **R**atched **MES**saging : An asynchronous end to end encrypted messaging socket application based on the signal protocol 


Contributions implementing features given in TODO (End of file) are welcome

### Overview
This is a group messaging/file transfer application that implements the signal protocol for secure encrypted communication.

- End to End encryption ensures the server learns nothing about messages and only acts as a relay
- Uses HMAC to verify ciphertext integrity and prevent ciphertext tampering
- Group messaging is end to end encrypted with each user using a unique sender key
- Sender Keys are shared on user addition using an asymmetrically encrypted channel created using a Diffie-Hellman key exchange
- Use of Sender keys allows message to be encrypted only once on client side and relies on server side fan out for efficient transfer 
- Key ratcheting is done after each message to ensure backward secrecy of ciphertext
- Application is asynchronous hence all users do not need to be online for key exchange
- Uses the socket library on python to connect server and client
- Available in CLI as well as GUI mode



### Dependencies
`Pycryptodome` needs to be installed. If `Pycrypto` is already installed, you need to uninstall it and install `Pycryptodome`; otherwise, you will get errors.

All other libraries used are included by default with Python.

### Security
This uses the signal protocol for an end to end encryption. For group end to end, encrypted messaging _**Sender Keys**_ are used to avoid encrypting the same message for each user. 

<img src="https://i0.wp.com/blog.trailofbits.com/wp-content/uploads/2019/08/image2-1.png?resize=690%2C638&ssl=1" width="300">

Note that the sender keys, however, have to be shared with each user without the server learning about them. This is done by a pairwise **Diffie-Hellman Key exchange**.

<img src="http://blog.trendmicro.com/trendlabs-security-intelligence/files/2015/09/anglerek_dh_01.jpg" width="500">

This step is done only on intialization if users and is <img src="https://render.githubusercontent.com/render/math?math=O(n^{2})"> where n is number of users.

#### The DFKE and Sender Key exchange is done as follows: 
- When initialized the server searches for a 2048 digit long random prime `p` which is shared over all users the base `g` used is fixed at `2`(Shown to have the same level of security)

```python
def initializeKeys(self):
    self.privateKey=(randint(1,int(self.p-1)))
    self.publicKey=pow(self.g,self.privateKey,self.p)
 ```
- When a new user is created a random integer in `[1,p)` `a` is chosen as the private key and <img src="https://render.githubusercontent.com/render/math?math=g^{a} mod p"> is taken to be the public key which is sent to the server.
- Each user calculates its **shared secret Diffie-Hellman key** with every other user <img src="https://render.githubusercontent.com/render/math?math=g^{ab}">
```python
def computeSharedKey(self,pubKey,toID):
  self.secretKeys[toId]=pow(self.publicKeys[toId],self.privateKey,self.p)
```
- The shared secret key between each user is passed through a Key Derivation Function(PBKDF2) to generate the actual secret key for the encrypted channel
- Now each user has a pairwise secret channel with each other user.
- Note: These secret pairwise channels if used directly for messaging would require each user to **encrypt each message `n-1` times** for each other user and cause much overhead. Instead we **use sender keys** and rely on **_server side fan out_** to send the message to each user.
- Now we generate a unique sender key for each user and use the **pairwise encrypted channels to communicate the key to each other user**
```python
 def encryptSenderKey(self,toUser):
    if(self.senderKey is None):
        self.senderKey=get_random_bytes(CIPHER_KEY_SIZE)
    sharedKey=KDF(self.secretKeys[toUser])
    cipher=AES.new(sharedKey,AES.MODE_EAX)
    nonce=cipher.nonce
    encryptedSenderKey,tag=cipher.encrypt
```
Notice how none of the above steps requires both parties to be online at the same time and hence the whole process is asynchronous

Note: On the addition of user, we only need to establish the new user's sender key by having a DFKE with each other user. All other sender keys remain intact.
Note: On deletion of user we need to reinitialize all keys to prevent eavesdropping by a deleted user, this is an expensive operation as it is <img src="https://render.githubusercontent.com/render/math?math=O(n^{2})">

This can be improved by using **Asynchronous Ratcheting Trees** (Todo), which need only logarithmic key changes on addition/deletion of user.

<img src="https://i2.wp.com/blog.trailofbits.com/wp-content/uploads/2019/08/post_remove_tree.png?resize=690%2C466&ssl=1" width="500">

Each message is encrypted with **AES-128** in **EAX mode** using a nonce and has a tag calculated using an HMAC attached with it to prevent ciphertext tampering. 

This ensures both **CCA(Chosen Ciphertext Attack) and CPA(Chosen Plaintext Attack) security**.

The end to end encryption ensures security against **man in the middle attacks** unless the server itself is compromised, which can only be verified by two parties independently verifying their public keys.

The key is also **ratcheted** after every message by running it through a **PBKDF2** this provides **backward secrecy** as the PBKDF2 uses **SHA-256** which is a one-way function, i.e. if at any point in time the sender key is compromised all messages before it is still safe. This, however, **does not provide forward secrecy** which can be ensured using **double ratcheting**(DFKE based) (Todo)


Now that sender keys are established, we can have communication.



### Communication
Socket library is used for server-client communication. Various types of messages are sent such as

1. Unencrypted server messages(utf-8 encoded)
2. Encrypted client messages(utf-8 encoded)
3. Raw Pickle objects

All messages have a message header, which specifies how many bytes long the message is. The entire message is received inside a buffer by the socket library.

The default buffer size is **4096** bytes. If longer messages need to be sent, increase this size in the `BUFSIZ` variable on both server and client-side.



### Misc 
Since we need to allow a login feature, the calculated keys and other information must be saved locally for each client. This is done by pickling the client object into a file.
The application also uses multithreading for simultaneous receiving and sending of messages.
The client runs 2 threads a send thread and a receive thread.
```python
receive_thread = Thread(target=receiveThread)
receive_thread.start()
swnd_thread = Thread(target=sendThread)
swnd_thread.start()
```
The server runs each client on a separate thread. This is a bottleneck, and running more than 100 threads on a standard processor is too intensive.
The key exchange and encryption protocols are implemented in utils.py

The GUI is made with TKinter library on python.

### Demo
Run server.py to setup server and client.py from multiple terminals to set up each client
If needed, the host and port can be changed from both the server and client files.
The default is

```python
HOST = '127.0.0.1'
PORT = 33001
```
For testing `Tmux` is great for managing multiple terminals.

![Terminal demo](demo.png?raw=true "Demo image")

#### GUI mode(new)
![GUI demo](gui.png?raw=true "Demo image")

The upper horizontal terminal is the server, and others are clients.


### Todo
- [x] Basic framework(Server, Client, Socket connections)
- [x] Multithreading for simultaneous message receiving and sending
- [x] User Addition
- [x] User login
- [x] Pickling client info to reduce login overhead
- [x] DHKE, Sender Keys, End to end encryption, HMAC verification
- [x] Single Ratcheting
- [x] Asynchronous additions/removals
- [x] Added basic GUI support
- [ ] Add file transfer support
- [ ] Add chatroom and login password authentication
- [ ] Reducing user addition overhead
- [ ] Message Storing for complete asynchronicity
- [ ] Delete user option(Keys should be reinitialized)
- [ ] Double ratcheting
- [ ] Improve GUI mode and design(add emoji support etc)
- [ ] Using Asynchronous Ratcheting Trees to improve asymptotic complexity



Contributions are Welcome!
