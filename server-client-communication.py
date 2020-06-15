from Crypto.Util import number
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random.random import randint
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
#install pycryptodome to work
#unsintall pycrypto

CIPHER_KEY_SIZE = 16 #AES-128

def KDF(sharedKey):
    derivedKey=PBKDF2(str(sharedKey),b"",dkLen=16)
    return derivedKey

class User(object):
    
    def __init__(self,id,p,g,isonline=True):
        
        self.id=id
        self.private_key=0
        self.public_key=0
        self.online=isonline
        self.dhkeComplete=False
        self.p=p
        self.g=g
        self.secretKeys={}
        self.senderKeys = {}
        self.senderKey=None
        self.idList=[]
        self.initializeKeys()

        
    
    def initializeKeys(self):
        self.private_key=(randint(1,int(self.p-1)))
        self.public_key=pow(self.g,self.private_key,self.p)
        
        
        
    def requestPublicKey(self):
        return self.public_key
    def computeSharedKey(self,toId):
        if(not self.dhkeComplete):
            
            if(toId==self.id):
                self.secretKeys[self.id]=0
            else:
                self.secretKeys[toId]=pow(self.server.publicKeys[toId],self.private_key,self.p)
        self.dhkeComplete=True
    def generateSenderKey(self):
        self.senderKey=get_random_bytes(CIPHER_KEY_SIZE)
        
    def sendSenderKey(self,toUser):
        if(self.senderKey is None):
            self.generateSenderKey()
        sharedKey=KDF(self.secretKeys[toUser])

        cipher=AES.new(sharedKey,AES.MODE_EAX)
        nonce=cipher.nonce
        encryptedSenderKey,tag=cipher.encrypt_and_digest(self.senderKey)
        
        
        return (nonce,encryptedSenderKey,tag)
        

    def receiveSenderKey(self,fromUser,data):
        nonce,encryptedSenderKey,tag = data
        sharedKey=KDF(self.secretKeys[fromUser])
        
        cipher = AES.new(sharedKey, AES.MODE_EAX,nonce=nonce)
        decryptedSenderKey=cipher.decrypt(encryptedSenderKey)
        try:
            cipher.verify(tag)
        except ValueError:
            print("MAC verification failed. Message may have been tampered with.")
            return False
        self.senderKeys[fromUser]=decryptedSenderKey

    def updateIdList(self):
        newLis=self.server.idList
        
        
        for i in newLis:
            if i not in self.idList:
                self.dhkeComplete=False
                self.computeSharedKey(i)
                self.idList.append(i)


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
        tmp = User(self,id, self.p, self.g) #send create message
        self.users[id]=tmp
        self.idList.append(id)
        self.publicKeys[id]=tmp.requestPublicKey()
        self.n+=1
        for i in self.idList:
            self.users[i].updateIdList()#When user is online should check updated users and update
            if i!=id:
                self.updatedUsers[i]=True
            else:
                self.updatedUsers[i]=False
        return tmp


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


