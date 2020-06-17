from Crypto.Util import number
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random.random import randint
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
#install pycryptodome to work
#unsintall pycrypto

CIPHER_KEY_SIZE = 16 #AES-128

def KDF(sharedKey,count=1000):
    derivedKey=PBKDF2(str(sharedKey),b"",dkLen=CIPHER_KEY_SIZE,count=count)
    return derivedKey

class User(object):
    
    def __init__(self,id,p,g,isonline=True):
        
        self.id=id
        self.privateKey=0
        self.publicKey=0        
        self.p=p
        self.g=g
        self.senderKey=None
        self.secretKeys={}
        self.publicKeys={}
        self.encryptedSenderKeys = {}
        self.decryptedSenderKeys={}
        self.initializeKeys()

    def initializeKeys(self):
        self.privateKey=(randint(1,int(self.p-1)))
        self.publicKey=pow(self.g,self.privateKey,self.p)
    def computeSharedKeys(self,pubKeys):
        self.publicKeys=pubKeys
        for toId in self.publicKeys:
            if toId not in self.secretKeys:
                if(toId==self.id):
                    self.secretKeys[self.id]=0
                else:
                    self.secretKeys[toId]=pow(self.publicKeys[toId],self.privateKey,self.p)
         
    def encryptSenderKey(self,toUser):
        if(self.senderKey is None):
            self.senderKey=get_random_bytes(CIPHER_KEY_SIZE)
        sharedKey=KDF(self.secretKeys[toUser])
        cipher=AES.new(sharedKey,AES.MODE_EAX)
        nonce=cipher.nonce
        encryptedSenderKey,tag=cipher.encrypt_and_digest(self.senderKey)        
        return (nonce,encryptedSenderKey,tag)
    def encryptSenderKeys(self):
        
        for toUser in self.publicKeys:
            
            self.encryptedSenderKeys[toUser]=self.encryptSenderKey(toUser)

    def decryptSenderKey(self,fromUser,data):
        nonce,encryptedSenderKey,tag = data
        sharedKey=KDF(self.secretKeys[fromUser])
        cipher = AES.new(sharedKey, AES.MODE_EAX,nonce=nonce)
        decryptedSenderKey=cipher.decrypt(encryptedSenderKey)
       
        try:
            cipher.verify(tag)
        except ValueError:
            print("MAC verification failed. Message may have been tampered with or ratcheting got out of sync")
            return False
        self.decryptedSenderKeys[fromUser]=decryptedSenderKey
        
    def decryptSenderKeys(self,encryptedSenderKeys):
        for fromUser in encryptedSenderKeys:
            
            self.decryptSenderKey(fromUser,encryptedSenderKeys[fromUser])
    


class Server(object):

    def __init__(self,prime_size=2048):
        self.n=0
        print("Finding Large Prime...")
        self.p=(number.getPrime(prime_size))
        self.idList=[]
        self.g=2
        self.users={}
        self.updatedUsers={}
        self.publicKeys={}
        print("Initializing Users...")
        
    
    def addUser(self,id):
        
        
        
        self.publicKeys[id]=tmp.requestPublicKey()
        
        for i in self.idList:
            self.users[i].updateIdList()#When user is online should check updated users and update
            if i!=id:
                self.updatedUsers[i]=True
            else:
                self.updatedUsers[i]=False
        


    def reinitializeUsers(self):
        self.publicKeys={}
        for i in self.idList:
            tmp = self.users[i]
            tmp.initializeKeys()
            self.publicKeys[i]=tmp.requestPublicKey()
        for i in self.idList:
            for j in self.idList:
                self.dhkExchange(i,j)


    
 
if __name__ == "__main__":       

    s=Server(15)
    u1=s.addUser(1)
    u2=s.addUser(3)
    u2=s.addUser(5)
    u2=s.addUser(6)
    u2=s.addUser(2)


    print(s.users[1].secretKeys)
    print(s.users[3].secretKeys)
    print(s.users[5].secretKeys)
    print(s.users[6].secretKeys)


