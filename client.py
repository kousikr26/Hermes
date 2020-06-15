
import pickle
from utils import User
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import sys
import os
import time
import utils
from Crypto.Cipher import AES
authenticated=False
def send(msg,client,raw=False,enc=False):
    if(not raw):
        msg = msg.encode('utf-8')
    if enc:
        aes=AES.new(user.senderKey,AES.MODE_EAX)
        nonce=aes.nonce
        encryptedMsg,tag=aes.encrypt_and_digest(msg)        
        msg=pickle.dumps((nonce,encryptedMsg,tag))
        
        
        
    message_header = f"{len(msg):<{HEADER_LENGTH}}".encode('utf-8')
    
    client_socket.send(message_header + msg)

def receive(client,raw=False):
    try:
        message_header = client.recv(HEADER_LENGTH)
        if not len(message_header):
            print("Message Header Not found")
        message_length = int(message_header.decode('utf-8').strip())
        if(raw):
            return client.recv(message_length)
        else:
            return client.recv(message_length).decode('utf-8')
    except:
        print("Message Header not in proper format ",message_header)
   
def checkCMD(cmd,msg):
    if(msg[0:len(cmd.lower())]==cmd.lower()):
        return True
    return False
            
def keyExchange(user,pubKeys):
    user.computeSharedKeys(pubKeys)
    user.encryptSenderKeys()

def receiveThread():
    global authenticated,user
    while True:            
        msge=receive(client_socket,raw=True)
        
        try:
        
            msg=msge.decode('utf8')
        except:
            
            msg=""
        
        
        if (checkCMD('!login success',msg) or checkCMD('!signup success',msg)):
            action="login" if checkCMD('!login success',msg) else "signup"
            infodump=receive(client_socket,raw=True)
            info=pickle.loads(infodump)
            if(action=="login"):
                with open("./data/"+info["id"],'rb') as userfile:  
                    user=pickle.load(userfile)


               
            else:
                user=User(info['id'],info['p'],info['g'])
                with open("./data/"+user.id,'wb+') as userfile:  
                    pickle.dump(user,userfile) 

                send(str(user.publicKey),client_socket)
            
            
           
       
        elif checkCMD("!new user",msg):
            send("!new user",client_socket)
            print("Adding user, please wait...")
            while(True):
                # try:
                if(1):
                    publicKeys=pickle.loads(receive(client_socket,raw=True))
                    
                    
                    if(user.id not in publicKeys):
                        publicKeys[user.id]=user.publicKey 
                    keyExchange(user,publicKeys)
                    
                    send(pickle.dumps(user.encryptedSenderKeys),client_socket,raw=True) 
                    tmp=receive(client_socket,raw=True)
                    
                    otherSenderKeys=pickle.loads(tmp)
                    
                    
                    user.decryptSenderKeys(otherSenderKeys)
                    
                    
                    with open("./data/"+user.id,'wb+') as userfile:  
                        pickle.dump(user,userfile) 

                    authenticated=True
                    break
                else:
                # except:
                    print("Waiting for server, please wait...")
                    time.sleep(0.5)
            
            
            
            
            
            
        elif checkCMD('!quit',msg):
            print("Terminating connection")
            client_socket.close()
            os._exit(1) 
        elif checkCMD('!broadcast',msg):
            print(msg[len("!broadcast"):])
        else:
            
            if(authenticated):
                
                fromUser=msge[:USERNAME_LENGTH].decode('utf8').strip()
                
                nonceRec,msgRec,tagRec=pickle.loads(msge[USERNAME_LENGTH:])
                if fromUser==user.id:
                    decipher = AES.new(user.senderKey, AES.MODE_EAX,nonce=nonceRec)
                else:
                    decipher = AES.new(user.decryptedSenderKeys[fromUser], AES.MODE_EAX,nonce=nonceRec)
                
                decMsgRec=decipher.decrypt(msgRec)
            
                try:
                    decipher.verify(tagRec)
                except ValueError:
                    print("MAC verification failed. Message may have been tampered with.")
                        
                print(fromUser+": "+decMsgRec.decode('utf8'))
            else:
                print(msg)
           

            
        

    
            
def sendThread():  
    """Handles sending of messages."""
    while True:
        msg = input("> ")
        print ("\033[A                             \033[A")
        if(authenticated and not checkCMD(msg,"!quit")):
            
            send(msg,client_socket,enc=True)
        else:
            send(msg,client_socket) 
       



HOST = '127.0.0.1'
PORT = 33001
if not os.path.exists('data'):
    os.makedirs('data')

BUFSIZ = 4096
ADDR = (HOST, PORT)
HEADER_LENGTH=10

USERNAME_LENGTH=50
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

receive_thread = Thread(target=receiveThread)
receive_thread.start()
swnd_thread = Thread(target=sendThread)
swnd_thread.start()
