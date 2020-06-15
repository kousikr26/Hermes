#!/usr/bin/env python3
"""Server for multithreaded (asynchronous) chat application."""
from socket import AF_INET, SOCK_STREAM
import socket
from threading import Thread
from utils import Server
import pickle
from Crypto.Util import number
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random.random import randint
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import time
greetings="""
    Welcome to the chatroom.
    1.  Existing user : !login
    2.  New user : !signup
    3.  Quit : !quit
"""

userToSocket={}
socketToUser={}
publicKeys={}
allEncryptedSenderKeys={}
recCount=0

def send(msg,client,raw=False):
    if(not raw):
        msg = msg.encode('utf-8')
    message_header = f"{len(msg):<{HEADER_LENGTH}}".encode('utf-8')
    
    client.send(message_header + msg)

def receive(client,raw=False):
    message_header=b''
    
    try:
        message_header = client.recv(HEADER_LENGTH)
        
        if not len(message_header):
            print("Header not found ",message_header)
            

        message_length = int(message_header.decode('utf-8').strip())
        if(raw):
            return client.recv(message_length)
        else:
            return client.recv(message_length).decode('utf-8')

    except:
        print("Receive error")

        # continue
def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s is attempting to connect." % client_address)
        Thread(target = authenticate,args=(client,)).start()
        

def checkCMD(cmd,msg):

    try:
        if(msg[0:len(cmd.lower())]==cmd.lower()):
            return True
    except:
        return False
    return False
               
        
def authenticate(client):
    global recCount
    send(greetings,client)
    initialized=False
    authenticated=False
    while True:

        cmde=receive(client,raw=True)
        print("received ",cmde)
        try:
            cmd=cmde.decode('utf8')
        except:
            cmd=""
        
        if(checkCMD("!login",cmd) or checkCMD("!signup",cmd)):
            initialized=True
            action="login" if checkCMD('!login',cmd) else "signup"
            send(action.title() +"\nEnter Username : ",client)
            uname=receive(client)
            if(action=="login"):
                if uname not in publicKeys:
                    send("Username does not exist, Try again.",client)
                    Thread(target = authenticate,args=(client,)).start()
                    return False
                if uname in userToSocket:
                    send("User is already logged in from a device",client)
                    Thread(target = authenticate,args=(client,)).start()
                    return False
            else:
                if uname in publicKeys or len(uname)>=USERNAME_LENGTH:

                    send("Username already exists or is too big. Try again.",client)
                    Thread(target = authenticate,args=(client,)).start()
                    return False
            userToSocket[uname]=client
            socketToUser[client]=uname
            info={'id':uname,'p':ServerObj.p,'g':ServerObj.g}
            infodump=pickle.dumps(info)
            send("!"+action+" success",client)
            send(infodump,client,True)
            recCount=0
            if(action=="signup"):
                pubKey=receive(client)
                publicKeys[uname]=int(pubKey)

                broadcast("!new user")
                
            else:
                broadcast("!new user")
                

        
        elif(checkCMD("!new user",cmd)):
            
            send(pickle.dumps(publicKeys),client,raw=True)
            
            allEncryptedSenderKeys[uname]=pickle.loads(receive(client,raw=True))
            recCount+=1
            while(recCount!=len(userToSocket)):
                print(recCount,len(userToSocket))
                print("Waiting for client...")
                time.sleep(0.5)
            
            # time.sleep(2)
            
            
            
            otherSenderKeys={}
            for otherUser in allEncryptedSenderKeys:
                if(otherUser!=uname):
                    try:
                        otherSenderKeys[otherUser]=allEncryptedSenderKeys[otherUser][uname]
                    except:
                        pass
            send(pickle.dumps(otherSenderKeys),client,raw=True)
            time.sleep(1.5)
            if(not authenticated):
                broadcast("%s has joined the chat." % uname,"!broadcast")
            authenticated=True


        elif(checkCMD("!quit",cmd)):
            print("Closing connection with client")
            exitUser=socketToUser[client]
            broadcast(exitUser+" has left the chat","!broadcast")
            send("!quit",client)
            
            
            del socketToUser[client]
            del userToSocket[exitUser]
            
            client.close()
            return False
            # broadcast("%s has left the chat." % name)
            
        elif initialized:
            
            broadcast(cmde, f"{uname:<{USERNAME_LENGTH}}".encode('utf8'),raw=True)
        else:
            send("Invalid option, Try again.",client)
            Thread(target = authenticate,args=(client,)).start()
            return False





def broadcast(msg, prefix="",raw=False):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    for sock in socketToUser:
        try:
            send(prefix+msg,sock,raw)
        except:
            pass
def relay(msg,toID,raw=False):
    send(msg,userToSocket[toID],raw)        

        

HOST = '127.0.0.1'
PORT = 33001
BUFSIZ = 4096
HEADER_LENGTH = 10
USERNAME_LENGTH=50
ADDR = (HOST, PORT)

SERVER = socket.socket(AF_INET, SOCK_STREAM)
SERVER.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
SERVER.bind(ADDR)
ServerObj=Server()
if __name__ == "__main__":
    SERVER.listen(5)
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()