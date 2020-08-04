
import pickle
from utils import User,CIPHER_KEY_SIZE,KDF
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import sys
import os
import time
import utils
from Crypto.Cipher import AES
import tkinter
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
def display(msg):
    if MODE=='GUI':
        msgs=list(msg.split('\n'))
        for i in msgs:
            msg_list.insert(tkinter.END, i)
    elif MODE=='CLI':
        print(msg)
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
            
            display("Adding user, please wait...")
            while(True):
                try:
                
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
                
                except:
                    display("Waiting for server, please wait...")
                    
                    time.sleep(0.5)
            
            
            
            
            
            
        elif checkCMD('!quit',msg):
            user.encryptSenderKeys()
            
            with open("./data/"+user.id,'wb+') as userfile:  
                pickle.dump(user,userfile) 
            display("Terminating connection")
            client_socket.close()
            os._exit(1) 
        elif checkCMD('!broadcast',msg):
            display(msg[len("!broadcast"):])
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
                    display("MAC verification failed. Message may have been tampered with or ratcheting got out of sync")
                if(fromUser!=user.id):
                    
                    
                    
                    display(fromUser+": "+decMsgRec.decode('utf8'))
                    user.decryptedSenderKeys[fromUser]=KDF(user.decryptedSenderKeys[fromUser],RATCHETING_STEPS)       
                    
                else:
                    display(fromUser+": "+decMsgRec.decode('utf8'))
                    user.senderKey=KDF(user.senderKey,RATCHETING_STEPS)

                  

            else:
                display(msg)
           

            
        

    
            
def sendThread():  
    """Handles sending of messages."""
    while True:
        msg = input("> ")
        print ("\033[A                             \033[A")
        if(authenticated and not checkCMD(msg,"!quit")):
            send(msg,client_socket,enc=True)
            
        else:
            
                
            send(msg,client_socket) 
def sendGUI(event=None):  # event is passed by binders.
    """Handles sending of messages in GUI mode"""
    msg = my_msg.get()
    my_msg.set("")  # Clears input field.
    
    if(authenticated and not checkCMD(msg,"!quit")):
        send(msg,client_socket,enc=True)
    elif(checkCMD(msg,"!quit")):
        send(msg,client_socket)    
        client_socket.close()
        top.quit()      
    else:                  
        send(msg,client_socket)    
def on_closing(event=None):
    """This function is to be called when the window is closed."""
    send("!quit",client_socket)
    client_socket.close()


MODE='GUI' #CLI mode or GUI
HOST = '127.0.0.1'
PORT = 33001
if not os.path.exists('data'):
    os.makedirs('data')

BUFSIZ = 4096
ADDR = (HOST, PORT)
HEADER_LENGTH=10

USERNAME_LENGTH=50
RATCHETING_STEPS=5
if (MODE=='GUI'):

    top = tkinter.Tk()
    top.title("Hermes")
    messages_frame = tkinter.Frame(top,borderwidth=5)
    my_msg = tkinter.StringVar()  # For the messages to be sent.
    my_msg.set("")
    scrollbar = tkinter.Scrollbar(messages_frame) 
    msg_list = tkinter.Listbox(messages_frame, height=50, width=80, yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
    msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
    msg_list.pack()
    messages_frame.pack()

    entry_field = tkinter.Entry(top,width='50', textvariable=my_msg)
    entry_field.bind("<Return>", sendGUI)
    entry_field.pack()
    send_button = tkinter.Button(top, text="Send", command=sendGUI)
    send_button.pack()
    top.protocol("WM_DELETE_WINDOW", on_closing)
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(ADDR)
    receive_thread = Thread(target=receiveThread)
    receive_thread.start()
    tkinter.mainloop()
   
elif (MODE=='CLI'):

    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(ADDR)

    receive_thread = Thread(target=receiveThread)
    receive_thread.start()

    swnd_thread = Thread(target=sendThread)
    swnd_thread.start()
