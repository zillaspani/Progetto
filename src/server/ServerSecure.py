import asyncio
from base64 import b64decode, b64encode
import logging
import random
import globalConstants as g
from server import Server
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
        root.add_resource(('heartbit',), Heartbit(s))
        root.add_resource(('authentication',), Authentication(s))
        root.add_resource(('dummy',), DummyResource(s))
        logging.info(f"Resource tree OK")
        await aiocoap.Context.create_server_context(root,bind=[g.IP,g.PORT])
        logging.info(f"Avvio server aiocoap su %s e porta %s",g.IP, g.PORT)
        await asyncio.get_running_loop().create_future()
        
    
    except Exception as ex:
        logging.error(ex)
        logging.error("Server cannot be instantiated")
        exit()
        
'''chiavi inizialmente messe qui per prova, 16 byte per AES, 32 per HMAC, da spostare il un file di configurazione poi'''
aes_key_sensore= b'8\x14>V\xb3\xbc`\xa4\xd1\x18\xb4}\xf2\x89\xbf\xd7'
hmac_key_sensore= b'Vlx\x1a(\x8b\xe5\xac@\xce \xff\xeb^\xd9\x19\xef\xc6\x98\x82\xa3\x9a\x89\xc09{\xe0\xfbB\x1a\xac\x0b'

aes_key_attuatore=b'u\xa3\\\x96\x08\x8e\xd3jc\x0f\xdbq3\xc4\x1d\xde'
hmac_key_attuatore=b'\xcbV\xfdU\xf5\xcf\xcb\xcczI\xa6p\xaf\xe8=\x18\x18\x17`\xe4\xb0\xaf$a\x0c/\xc8\xach\xda\x92\xc2'

public_sensor_key=''
public_actuator_key=''

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
    
def cript_dictionary_to_payload(dictionary,key):
    '''metodo che prende in input un dictionary e restituisce lo stesso cifrato in bytes, facendo uso di encrypt_aes'''
    cript_in_string=encrypt_aes(json.dumps(dictionary).encode("utf-8"),key)
    cript_in_json=json.loads(cript_in_string)
    tag= tag_hmac_sha256(cript_in_json['ciphertext'], hmac_key_attuatore)
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

''''''

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
            check_payload(request_json['ciphertext'], request_json['tag'], hmac_key_sensore) #OK
            #request_json['ciphertext'] è una stringa
            plaintext=decrypt_aes(request_json['iv'],request_json['ciphertext'], aes_key_sensore)
            request_json=json.loads(plaintext)
            print(request_json)
            if not self.server.checkData(request_json):#:)
                logging.warning("Values not good")
                raise Exception("Bad values")
            self.server.addData(request_json)
            return aiocoap.Message(code=aiocoap.CHANGED)
        except ValueError as Ve:
            logging.error("Exception in DataResource "+ Ve)
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)
        except Exception as Ex:
            logging.error("Exception in DataResource "+ str(Ex))
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)
        

class Heartbit(resource.Resource):
    def __init__(self,s):
        super().__init__()
        self.server=s

    '''
    Riceve delle get da attuatore e sensore per sapere se stann bene
    '''

    async def render_get(self,request):
        try:
            request_json=json.loads(request.payload.decode())
            ip=self.server.address_parser(request.remote.hostinfo)['address']
            self.server.timestamp[ip]=request_json['time_stamp']
            logging.info("HealtRequest Handling Success")
            return aiocoap.Message(code=aiocoap.CHANGED)

        except Exception:
            logging.info("HealtRequest Handling failed")
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)

class Authentication(resource.Resource):
    s=None
    key_session=None
   
    def __init__(self,s):
        super().__init__()
        self.s=s
        key_session=None
        
    
    async def render_get(self, request):
        try:
            request_string=json.loads(request.payload.decode())
            request_json=json.loads(request_string)
            '''
            per la versione definitiva andrà a prendere dalle strutture preconfigurate
            va aggiustato per capire meglio la configurazione del file json, passato in json a posta per prendersi meglio
            i valori, in questo caso dato per scontato
            sarà qualcosa che si prende la chiave pubblica in questo caso la prende in maniera hardcodatissima
            '''
            if request_json['type']=='sensori':
                pck=RSA.import_key(open("./src/server/public_sensore.pem").read())
            elif request_json['type']=='attuatori':
                pck=RSA.import_key(open("./src/server/public_attuatore.pem").read())
            else:
                raise Exception("Type not defined")
            # Encrypt the session key with the public RSA key
            session_key = get_random_bytes(16)
            cipher_rsa = PKCS1_OAEP.new(pck)
            enc_session_key_bytes = cipher_rsa.encrypt(session_key)
            self.key_session=str(random.randint(1000000000000000000000000000000000, 1000000000000000000000000000000000000000000000000000))
            secret=self.key_session.encode("utf-8") #numero molto grande
            # Encrypt the data with the AES session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext_bytes, tag_bytes = cipher_aes.encrypt_and_digest(secret)
            tag = b64encode(tag_bytes).decode('utf-8')
            ct = b64encode(ciphertext_bytes).decode('utf-8')
            enc_session_key = b64encode(enc_session_key_bytes).decode('utf-8')
            payload_string= json.dumps({'enc_session_key':enc_session_key, 'tag':tag, 'ciphertext':ct, 'nonce':b64encode(cipher_aes.nonce).decode('utf-8')})
            payload=json.dumps(payload_string).encode("utf-8")
            logging.info("Challenge inviata correttamente")
            return aiocoap.Message(payload=payload)
            
        except Exception as Ex:
            logging.error("Exception in DataResource "+ str(Ex))
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)
        
    async def render_post(self, request):
        try:
            request_string=json.loads(request.payload.decode())
            request_json=json.loads(request_string)
            #assegnamo i campi che risulteranno stringhe
            enc_session_key=request_json["enc_session_key"]
            tag =request_json["tag"]
            ciphertext=request_json["ciphertext"]
            nonce=request_json["nonce"]
            private_key = RSA.import_key(open("./src/server/private_server.pem").read())
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
            secret=secret_byte.decode("utf-8")
            if secret!=self.key_session:
                raise Exception("The challenge was unsuccessful")
            #se sono uguali bisogna mandargli una chiave segreta per aes e mac cifrata con la chiave pubblica del client
            print("TUTTO OK FINO AD ADESSO SBORROOOOOOOO")
            return 
        except Exception as Ex:
            logging.error("Exception in DataResource "+ str(Ex))
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)

        

class ReceiveState(resource.Resource):
    '''
    Riceve una get dal sensore e restituisce una:
    risposta con codice 2.05
    Attuatore deve inviare un messaggio confermabile
    '''
    s=None
    def __init__(self,s):
        super().__init__()
        self.s=s
        
    
    
    async def render_get(self, request):
        '''
        get request handling from actuators
        '''
        try:
            ip="192.168.1.3"    
            comportamento=self.s.getBehave(ip)
            state={'state':comportamento}
            state_cript_in_bytes=cript_dictionary_to_payload(state,aes_key_attuatore)
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
    
    