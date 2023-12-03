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
from Crypto.Hash import HMAC, SHA256,SHA384
from colorama import Fore
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Util.number import getPrime

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
        root.add_resource(('handshake',), Handshake(s))
        root.add_resource(('dummy',), DummyResource(s))
        logging.info(f"Resource tree OK")
        await aiocoap.Context.create_server_context(root,bind=[g.IP,g.PORT])
        logging.info(f"Avvio server aiocoap su %s e porta %s",g.IP, g.PORT)
        await asyncio.get_running_loop().create_future()
        
    
    except Exception as ex:
        logging.error(ex)
        logging.error("Server cannot be instantiated")
        exit()
        
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
    tag= tag_hmac_sha(cript_in_json['ciphertext'], key_hmac)
    result=json.dumps({'iv':cript_in_json['iv'], 'ciphertext':cript_in_json['ciphertext'], 'tag':tag})
    payload=json.dumps(result).encode("utf-8") 
    return payload

def check_payload(ct, tag, key):
    check=tag_hmac_sha(ct, key)
    if tag!=check:
        logging.warning("Wrong tag")
        raise Exception("Wrong tag")
    return

def check_signature(public_key_client, signature_bytes):
    hash_object = SHA256.new(public_key_client.export_key('PEM'))
    try:
        pkcs1_15.new(public_key_client).verify(hash_object, signature_bytes)
        print("Signature is valid.")
    except (ValueError, TypeError):
         raise Exception("Wrong signature")
    

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
    
def tag_hmac_sha(data, key):
        '''
        Semplice metodo per calcolare il tag con HMAC-Sha384, dove data in questo caso è una stringa
        '''
        h = HMAC.new(key, digestmod=SHA384)
        h.update(str.encode(data))
        tag=b64encode(h.digest()).decode('utf-8')
        #ritorna un tag a stringa
        return tag 

def open_public_client_key(server,ip):
    tipo=server.getTipo(ip)
    if tipo=='sensors':
        return RSA.import_key(open("../src/server/keys/public_sensore.pem").read())
    elif tipo=='actuators':
        return RSA.import_key(open("../src/server/keys/public_attuatore.pem").read())

def get_aes(ip):
    return keys[ip]["aes_key"]
        
        
def get_hmac(ip):
    return keys[ip]["hmac_key"]

def private_server_key_decrypt(request_string, path_private_key):
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
                 
def encrypt_with_rsa(pck,secret_string):
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
            request_json=json.loads(request_string)
            ''''''
            pck=open_public_client_key(self.server, ip)
            check_payload(request_json['ciphertext'], request_json['tag'], hmac_key) #OK
            #request_json['ciphertext'] è una stringa
            plaintext=decrypt_aes(request_json['iv'],request_json['ciphertext'], aes_key)
            #check_signature(plaintext, request_json['signature'],pck)
            request_json=json.loads(plaintext)
            if not self.server.checkData(request_json):#:)
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
        
class Handshake(resource.Resource):
    server=None
    def __init__(self,s):
        super().__init__()
        self.server=s
        self.p_aes=0
        self.p_hmac=0
        self.private_dh_key_aes=None
        self.private_dh_key_hmac=None
    
    def add_keys(self,ip, aes, hmac):
        keys[ip]={'aes_key': aes, 'hmac_key':hmac}
          
    async def render_get(self,request):
        '''
        get request handling from sensors
        '''
        try: 
        
            ip=self.server.address_parser(request.remote.hostinfo)['address']
            request_string=json.loads(request.payload.decode())
            request_json=json.loads(request_string)
            private_server_key= RSA.import_key(open("../src/server/keys/private_server.pem").read())
            data_str=b64decode(request_json['encrypted_key'])
            data_string=json.loads(data_str.decode())
            encrypt_key_byte=private_server_key_decrypt(data_string,"../src/server/keys/private_server.pem")
            signature_str=request_json['signature'] 
            signature_b=b64decode(signature_str)
            public_key_sender=open_public_client_key(self.server ,ip)
            check_signature(public_key_sender,signature_b)
            #HO IN BYTE LA CHIAVE PUBBLICA DEL CLIENT E LA SUA FIRMA DIGITALE
            self.p_aes = getPrime(256)
            g = 2
            self.private_dh_key_aes = get_random_bytes(32)
            public_dh_key_aes = pow(g, int.from_bytes(self.private_dh_key_aes, 'big'), self.p_aes)
            public_dh_key_byte_aes=public_dh_key_aes.to_bytes((public_dh_key_aes.bit_length() + 7) // 8, 'big')
            key_aes_str=b64encode(public_dh_key_byte_aes).decode('utf-8')
            self.p_hmac = getPrime(256)
            self.private_dh_key_hmac = get_random_bytes(32)
            public_dh_key_hmac = pow(g, int.from_bytes(self.private_dh_key_hmac, 'big'), self.p_hmac)
            public_dh_key_byte_hmac=public_dh_key_hmac.to_bytes((public_dh_key_hmac.bit_length() + 7) // 8, 'big')
            key_hmac_str=b64encode(public_dh_key_byte_hmac).decode('utf-8')
            
            result = json.dumps({'p_aes':self.p_aes, 'public_key_string_aes':key_aes_str, 'p_hmac':self.p_hmac,'public_key_string_hmac':key_hmac_str})
            payload=json.dumps(result).encode("utf-8")
            return aiocoap.Message(payload=payload)
        except ValueError as Ve:
            logging.error("Exception in HandashakeGET "+ Ve)
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)
        except Exception as Ex:
            logging.error("Exception in HandshakeGET "+ str(Ex))
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)


    async def render_post(self,request):
        try:
            # Step 5: Ricevi la chiave pubblica Diffie-Hellman cifrata dal client
            request_string = json.loads(request.payload.decode())
            request_json=json.loads(request_string)
            #parte di aes:
            encrypted_client_dh_key_aes=b64decode(request_json['aes'])
            client_dh_key_aes = int.from_bytes(encrypted_client_dh_key_aes, 'big')
            shared_secret_aes = pow(client_dh_key_aes, int.from_bytes(self.private_dh_key_aes, 'big'), self.p_aes)
            shared_secret_bytes_aes = shared_secret_aes.to_bytes((shared_secret_aes.bit_length() + 7) // 8, 'big')
        
            #parte hmac
            encrypted_client_dh_key_hmac=b64decode(request_json['hmac'])
            client_dh_key_hmac = int.from_bytes(encrypted_client_dh_key_hmac, 'big')
            
            shared_secret_hmac = pow(client_dh_key_hmac, int.from_bytes(self.private_dh_key_hmac, 'big'), self.p_hmac)
            shared_secret_bytes_hmac = shared_secret_hmac.to_bytes((shared_secret_hmac.bit_length() + 7) // 8, 'big')
            
            ip=self.server.address_parser(request.remote.hostinfo)['address']
            self.add_keys(ip,shared_secret_bytes_aes,shared_secret_bytes_hmac)
            print("Handshake completato correttamente, calcolo delle chiavi per AES e HMAC completato")
            
            return aiocoap.Message(code=aiocoap.CREATED, payload=b"Handshake completato con successo")
            
        except ValueError as Ve:
            logging.error("Exception in Handashake "+ Ve)
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)
        except Exception as Ex:
            logging.error("Exception in Handshake "+ str(Ex))
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
    


        

'''
TO DO:
Sistema che ricevuto un dato e l'indirizzo IP effettui controlli base sui valori
come formato, segno etc poi valuta la coerenza del dato in relazione agli altri
dati disponibili con media comulativa.
WARNING NEL CASO IN CUI IL VALORE CORRENTE RICEVUTO SIA DISCORDE CON LA MEDIA CUMILATIVA
'''
    

'''
TO DO: Capire come gestire le politiche di istradamento e federazione
'''

'''
Console carina e coccolosa per le informazioni
'''


class DummyResource():
    def __init__(self,s) -> None:
        pass
    async def render_get(self, request):
        logging.info("Qui arriva")
        text = ["Request came from %s." % request.remote.hostinfo]
        print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        text.append("The server address used %s." % request.remote.hostinfo_local)

        return aiocoap.Message(content_format=0, payload="CCC\n".join(text).encode('utf8'))


if __name__ == "__main__":
    signal.signal(signal.SIGINT, close)
    asyncio.run(main())
    
    