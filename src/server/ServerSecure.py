import asyncio
from base64 import b64decode, b64encode
import logging
import os
import random
import globalConstants as g
from Server import Server
from aiocoap import resource
import aiocoap
import json
import signal
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from colorama import Fore
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

'''chiavi inizialmente messe qui per prova, 16 byte per AES, 32 per HMAC, da spostare il un file di configurazione poi'''
keys={}


def close(signum, frame):
    handlers = logging.handlers[:]
    for handler in handlers:
        logging.removeHandler(handler)
        handler.close()
        logging.shutdown()
        exit()
    
async def main():
    try:
        s=Server()
        root = aiocoap.resource.Site()
        root.add_resource(('data',), DataResource(s))
        root.add_resource(('receive',), ReceiveState(s))
        root.add_resource(('authentication',), Authentication(s))
        logging.info(f"Resource tree OK")
        await aiocoap.Context.create_server_context(root,bind=[g.IP,g.PORT])
        logging.info(f"Avvio server aiocoap su %s e porta %s",g.IP, g.PORT)
        await asyncio.get_running_loop().create_future()
        
    
    except Exception as ex:
        logging.error(ex)
        logging.error("Server cannot be instantiated")
        exit()
        
def encrypt_aes_easy(data, key):
        cipher=AES.new(key,AES.MODE_ECB)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        result=b64encode(ct_bytes).decode('utf-8')
        return result
    
def encrypt_aes(data, key):
        '''
        Metodo che cifra con AES, dove data e key sono in bytes
        '''
        cipher=AES.new(key,AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv':iv, 'ciphertext':ct})
        '''ritorna una stringa'''
        return result
    
def cript_dictionary_to_payload(dictionary,key_aes,key_hmac):
    '''metodo che prende in input un dictionary e restituisce lo stesso cifrato in bytes, facendo uso di encrypt_aes'''
    cript_in_string=encrypt_aes(json.dumps(dictionary).encode("utf-8"),key_aes)
    cript_in_json=json.loads(cript_in_string)
    tag= tag_hmac_sha256(cript_in_json['ciphertext'], key_hmac)
    result=json.dumps({'iv':cript_in_json['iv'], 'ciphertext':cript_in_json['ciphertext'], 'tag':tag})
    #AGGIUNTA QUI
    '''
    si usa result se si fa in modo di sniffare in chiaro i campi del json
    mentre result_cripto per nascondere anche quelli
    '''
    #result_cripto=encrypt_aes_easy(result.encode(), aes_key_attuatore)
    #payload=json.dumps(result_cripto).encode("utf-8")
    
    ''''''
    payload=json.dumps(result).encode("utf-8") 
    return payload

def check_payload(ct, tag, key):
    check=tag_hmac_sha256(ct, key)
    if tag!=check:
        logging.warning("Wrong tag")
        raise Exception("Wrong tag")
    return

def decrypt_aes_easy(ct, key):
    '''metodo in cui ct è una stringa e key invece bytes'''
    bytes_ct=b64decode(ct)
    cipher = AES.new(key, AES.MODE_ECB)
    pt = unpad(cipher.decrypt(bytes_ct), AES.block_size)
    #return plaintext in string, ma con struttura json
    return pt.decode()

def decrypt_aes(iv, ct, key):
    '''
    ct e iv inizialmente passati come stringhe
    '''
    bytes_iv=b64decode(iv)
    bytes_ct=b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, bytes_iv)
    pt = unpad(cipher.decrypt(bytes_ct), AES.block_size)
    #return plaintext in string, ma con struttura json
    return pt.decode()
    
def tag_hmac_sha256(data, key):
        '''
        Semplice metodo per calcolare il tag con HMAC-Sha256, dove data in questo caso è una stringa
        '''
        h = HMAC.new(key, digestmod=SHA256)
        h.update(str.encode(data))
        tag=b64encode(h.digest()).decode('utf-8')
        #ritorna un tag a stringa
        return tag 

def get_aes(ip):
    return keys[ip]["aes_key"]
        
        
def get_hmac(ip):
    return keys[ip]["hmac_key"]
     
class DataResource(resource.Resource):      
    '''
    Riceve una get dal sensore e restituisce una:
    risposta con codice 2.05
    '''
    server=None
    def __init__(self,s):
        super().__init__()
        self.server=s  
     
    async def render_get(self, request):
        '''
        get request handling from sensors
        '''
        try: 
            ip=self.server.address_parser(request.remote.hostinfo)['address']
            '''prendiamo le chiavi scambiate'''
            aes_key=get_aes(ip)
            hmac_key=get_hmac(ip)
            
            '''
            aggiunta crittografia
            '''
            request_string=json.loads(request.payload.decode())
            '''
            versione con doppia cifratura
            '''
            #request_string_easy=decrypt_aes_easy(request_string,aes_key_sensore)
            #request_json=json.loads(request_string_easy)
            
            '''
            versione standard
            '''
            request_json=json.loads(request_string)
            ''''''
            check_payload(request_json['ciphertext'], request_json['tag'], hmac_key) #OK
            #request_json['ciphertext'] è una stringa
            plaintext=decrypt_aes(request_json['iv'],request_json['ciphertext'], aes_key)
            request_json=json.loads(plaintext)
            print(request_json)
            if not self.server.checkData(request_json):
                logging.warning("Values not good")
                raise Exception("Bad values")
            self.server.addData(request_json,ip)
            return aiocoap.Message(code=aiocoap.CHANGED)
        except ValueError as Ve:
            logging.error("Exception in DataResource "+ Ve)
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)
        except Exception as Ex:
            logging.error("Exception in DataResource "+ str(Ex))
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)
        



class Authentication(resource.Resource):
    server=None   
    def __init__(self,s):
        super().__init__()
        self.server=s
   
    def add_keys(self,ip, aes, hmac):
        keys[ip]={'aes_key': aes, 'hmac_key':hmac}
              
    def encrypt_with_rsa(self,pck,secret_string):
        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(pck)
        enc_session_key_bytes = cipher_rsa.encrypt(session_key)
        secret=secret_string.encode("utf-8")
        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext_bytes, tag_bytes = cipher_aes.encrypt_and_digest(secret)
        tag = b64encode(tag_bytes).decode('utf-8')
        ct = b64encode(ciphertext_bytes).decode('utf-8')
        enc_session_key = b64encode(enc_session_key_bytes).decode('utf-8')
        payload_string= json.dumps({'enc_session_key':enc_session_key, 'tag':tag, 'ciphertext':ct, 'nonce':b64encode(cipher_aes.nonce).decode('utf-8')})
        payload=json.dumps(payload_string).encode("utf-8")
        return payload
    
    def private_server_key_decrypt(self, request_string, path_private_key):
        request_json=json.loads(request_string)
        #assegnamo i campi che risulteranno stringhe
        enc_session_key=request_json["enc_session_key"]
        tag =request_json["tag"]
        ciphertext=request_json["ciphertext"]
        nonce=request_json["nonce"]
        private_key = RSA.import_key(open(path_private_key).read())
        enc_session_key_bytes=b64decode(enc_session_key)
        tag_bytes = b64decode(tag)
        ct_bytes = b64decode(ciphertext)
        nonce_bytes=b64decode(nonce.encode())
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key_bytes)
        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce_bytes)
        secret_byte = cipher_aes.decrypt_and_verify(ct_bytes, tag_bytes)
        return secret_byte
    
    def open_public_client_key(self, request):
        ip=self.server.address_parser(request.remote.hostinfo)['address']
        tipo=self.server.getTipo(ip)
        if tipo=='sensors':
            return RSA.import_key(open("../src/server/keys/public_sensore.pem").read())
        elif tipo=='actuators':
            return RSA.import_key(open("../src/server/keys/public_attuatore.pem").read())
            
    async def render_get(self, request):
        try:
            ip=self.server.address_parser(request.remote.hostinfo)['address']
            request_string=json.loads(request.payload.decode())
            request_json=json.loads(request_string)
            if self.server.getTipo(ip)!=request_json["type"]:
                #print(request_json["type"])
                raise Exception("Type not defined")
            pck=self.open_public_client_key(request)

           # Encrypt the session key with the public RSA key
            self.challenge=str(random.randint(g.INT_LOWER,g.INT_GREATER))
            payload=self.encrypt_with_rsa(pck,self.challenge)
            logging.info("Challenge inviata correttamente")
            return aiocoap.Message(payload=payload)   
        except Exception as Ex:
            logging.error("Exception in AuthenticationGet "+ str(Ex))
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)
        
    async def render_post(self, request):
        try:
            pck=self.open_public_client_key(request)
            request_string=json.loads(request.payload.decode())
            secret_byte=self.private_server_key_decrypt(request_string,"../src/server/keys/private_server.pem")
            secret=secret_byte.decode("utf-8")
            if secret!=self.challenge:
                raise Exception("The challenge was unsuccessful")
            #se sono uguali bisogna mandargli una chiave segreta per aes e mac cifrata con la chiave pubblica del client
            key_aes=os.urandom(16)
            key_hmac=os.urandom(32)
            ip=self.server.address_parser(request.remote.hostinfo)['address']
            self.add_keys(ip,key_aes,key_hmac)
            '''queste due chiavi ora devono essere mandate al client'''
            key_aes_string= b64encode(key_aes).decode('utf-8')
            key_hmac_string = b64encode(key_hmac).decode('utf-8')
            keys_ciphertext_string= json.dumps({'aes':key_aes_string, 'hmac':key_hmac_string})
            payload=self.encrypt_with_rsa(pck, keys_ciphertext_string)
            logging.info("Autenticazione riuscita, chiavi inviate correttamente")
            return aiocoap.Message(payload=payload) 
        except Exception as Ex:
            logging.error("Exception in AuthenticationPost "+ str(Ex))
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)

        

class ReceiveState(resource.Resource):
    '''
    Riceve una get dal sensore e restituisce una:
    risposta con codice 2.05
    Attuatore deve inviare un messaggio confermabile
    '''
    server=None
    def __init__(self,s):
        super().__init__()
        self.server=s
        
    
    
    async def render_get(self, request):
        '''
        get request handling from actuators
        '''
        try:
            ip=self.server.address_parser(request.remote.hostinfo)['address'] 
            comportamento=self.server.getBehave(ip)
            state={'state':comportamento}
            aes_key=get_aes(ip)
            hmac_key=get_hmac(ip)
            state_cript_in_bytes=cript_dictionary_to_payload(state,aes_key,hmac_key)
            return aiocoap.Message(payload=state_cript_in_bytes)
        except ValueError:
            logging.info("ReceiveState Handling failed")
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, close)
    asyncio.run(main())
    
    