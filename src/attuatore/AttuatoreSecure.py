from base64 import b64decode, b64encode
import time
import json
import asyncio
import aiocoap
import logging
from aiocoap import *
from Attuatore import Attuatore
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


class AttuatoreSecure(Attuatore):
    '''chiavi inizialmente messe qui per prova, 16 byte per AES, 32 per HMAC, da spostare il un file di configurazione poi'''
    aes_key=b''
    hmac_key=b''

    def check_payload(self, ct, tag, key): 
        check=self.tag_hmac_sha256(ct, key)
        if tag!=check:
            logging.warning("Wrong tag")
            raise Exception("Wrong tag")
        return

    def decrypt_aes_easy(self, ct, key):
        '''metodo in cui ct è una stringa e key invece bytes'''
        bytes_ct=b64decode(ct)
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(bytes_ct), AES.block_size)
        #return plaintext in string, ma con struttura json
        return pt.decode()

    def decrypt_aes(self,iv, ct, key):
        '''
        ct e iv inizialmente passati come stringhe
        '''
        bytes_iv=b64decode(iv)
        bytes_ct=b64decode(ct)
        cipher = AES.new(key, AES.MODE_CBC, bytes_iv)
        pt = unpad(cipher.decrypt(bytes_ct), AES.block_size)
        #return plaintext in string, ma con struttura json
        return pt.decode()
        
    def tag_hmac_sha256(self, data, key):
            '''
            Semplice metodo per calcolare il tag con HMAC-Sha256, dove data in questo caso è una stringa
            '''
            h = HMAC.new(key, digestmod=SHA256)
            h.update(str.encode(data))
            tag=b64encode(h.digest()).decode('utf-8')
            #ritorna un tag a stringa
            return tag 
        
    def private_client_key_decrypt(self, response_string, path_private_key):
        response_json=json.loads(response_string)
        #assegnamo i campi che risulteranno stringhe
        enc_session_key=response_json["enc_session_key"]
        tag =response_json["tag"]
        ciphertext=response_json["ciphertext"]
        nonce=response_json["nonce"]
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
        
    def public_server_key_encrypt(self,secret_byte, path_public_key):
        psk=RSA.import_key(open(path_public_key).read())
        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(psk)
        enc_session_key_bytes = cipher_rsa.encrypt(session_key)
         # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext_bytes, tag_bytes = cipher_aes.encrypt_and_digest(secret_byte)
        tag = b64encode(tag_bytes).decode('utf-8')
        ct = b64encode(ciphertext_bytes).decode('utf-8')
        enc_session_key = b64encode(enc_session_key_bytes).decode('utf-8')
        payload_string= json.dumps({'enc_session_key':enc_session_key, 'tag':tag, 'ciphertext':ct, 'nonce':b64encode(cipher_aes.nonce).decode('utf-8')})
        payload=json.dumps(payload_string).encode("utf-8")
        return payload
    
    async def authentication_client(self):
        endpoint=self.server_uri+"authentication"
        '''
        TO DO
        hello_str già pensato per inviare al server un json da poter ricercare in config.json del server dove
        verranno aggiunti le chiavi pubbliche dei sensori e attuatori
        '''
        hello_str= json.dumps({'type':'actuators'})
        payload=json.dumps(hello_str).encode("utf-8") #byte
        response_hello=await self.send_get_request(endpoint,payload=payload)
        
        #il client ha ricevuto un messaggio dal server contenente la challenge
        response_string=json.loads(response_hello.payload.decode())
        secret_byte=self.private_client_key_decrypt(response_string,"../src/attuatore/keys/private_attuatore.pem")

        #ora si cifra con la chiave pubblica del server e si manda la risposta
        payload=self.public_server_key_encrypt(secret_byte,"../src/sensore/keys/public_server.pem")
       
        response_challenge=await self.send_post_request(endpoint,payload=payload)
        #il client ha ricevuto le chiavi e se le prende
        response_string=json.loads(response_challenge.payload.decode())
        secret_byte=self.private_client_key_decrypt(response_string,"../src/attuatore/keys/private_attuatore.pem")
        
        secret_json=json.loads(secret_byte.decode())
        self.aes_key= b64decode(secret_json["aes"])
        self.hmac_key=b64decode(secret_json["hmac"])
        logging.info("Autenticazione riuscita, chiavi correttamente memorizzate")
        
    async def state_request(self):
        '''
        Invia una richiesta al server per conoscere in quale stato deve essere l'attuatore
        '''
        endpoint=self.server_uri+"receive"
        response=await self.send_get_request(endpoint,None)
        '''QUI SI GESTISCE'''
        response_string=json.loads(response.payload.decode())
        '''
        aggiunta crittografia'''
        '''
        versione con doppia cifratura
        '''
        #response_string_easy=decrypt_aes_easy(response_string,self.aes_key)
        #response_json=json.loads(response_string_easy)
        
        '''
        versione standard
        '''
        request_json=json.loads(response_string)
        ''''''
        self.check_payload(request_json['ciphertext'], request_json['tag'], self.hmac_key) #OK
        #request_json['ciphertext'] è una stringa
        plaintext=self.decrypt_aes(request_json['iv'],request_json['ciphertext'], self.aes_key)
        response_json=json.loads(plaintext) 
        if response==None:
            logging.error("Something went wrong during server request handling")
        else:
            if response_json['state']!="trap":
                self.set_stato=response_json['state']
                logging.info("State Changed")
            else:
                logging.info("State Not Changed")
                  
    async def send_get_request(self, endpoint,payload):
        '''
        Metodo che invia ad un endpoint una get con payload opzionale e restituisce la risposta alla richiesta, restiutisce None in caso di insuccesso
        '''
        try:
            protocol = await aiocoap.Context.create_client_context()
            if payload==None:
                request = aiocoap.Message(code=aiocoap.GET, uri=endpoint)
            else:
                request = aiocoap.Message(code=aiocoap.GET, uri=endpoint,payload=payload)
            logging.info("Richiesta inviata")

            response = await protocol.request(request).response
        except aiocoap.error.RequestTimedOut:
            logging.info("Richiesta al server CoAP scaduta")
            return None
        if response.code.is_successful():
            try:
                logging.info("Il server ha inviato una risposta valida")
                return response
            except ValueError:
                logging.info("Il server ha inviato una risposta non valida")
                return None
        else:
            logging.info(f"Errore nella risposta del server: {response.code}")
            return None
        
    async def send_post_request(self, endpoint,payload):
        '''
        Metodo che invia ad un endpoint una post e restituisce la risposta alla richiesta, restiutisce None in caso di insuccesso
        '''
        try:
            protocol = await aiocoap.Context.create_client_context()
            request = Message(code=aiocoap.POST, uri=endpoint, payload=payload)
            logging.info("Richiesta inviata")

            response = await protocol.request(request).response
        except aiocoap.error.RequestTimedOut:
            logging.info("Richiesta al server CoAP scaduta")
            return None
        if response.code.is_successful():
            try:
                logging.info("Il server ha inviato una risposta valida")
                return response
            except ValueError:
                logging.info("Il server ha inviato una risposta non valida")
                return None
        else:
            logging.info(f"Errore nella risposta del server: {response.code}")
            return None 
    
def main():
    attuatore= AttuatoreSecure()
    logging.info("iter="+str(attuatore.max_iter))
  
    try:
        if  attuatore.mode=="loop":
            iter=0
            loop=asyncio.get_event_loop()
            loop.run_until_complete(attuatore.authentication_client())
            while True:
                time.sleep(attuatore.time_unit)
                #Inserire qui i metodi di routine
                loop.run_until_complete(attuatore.state_request())
                #fine metodi di routine
                iter=iter+1
                if iter == attuatore.max_iter:
                    exit("Max iters reached")
        else:
            logging.info("Console mode:")
            logging.info("-1 StateRequest\n-0 Exit")
            while True:
                run_command(attuatore,input(">"))

    except Exception as ex:
        logging.error(ex)
        logging.error("Actuator cannot be instantiated")
        exit()

def run_command(attuatore,cmd):
    loop=asyncio.get_event_loop()
    if cmd == '1':
        loop.run_until_complete(attuatore.state_request())
    elif cmd == '0':
        exit("Bye")
    else:
        logging.info("Comando non valido, repeat")

if __name__ == "__main__":
    asyncio.run(main())