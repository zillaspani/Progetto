from base64 import b64decode, b64encode
import os
import time
import psutil
import aiocoap
import asyncio
import json
import logging
from aiocoap import *
from colorama import Fore
from Sensore import Sensore
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

class SensoreSecure(Sensore):
    '''chiavi inizialmente messe qui per prova, 16 byte per AES, 32 per HMAC, da spostare il un file di configurazione poi'''
    aes_key= b'8\x14>V\xb3\xbc`\xa4\xd1\x18\xb4}\xf2\x89\xbf\xd7'
    hmac_key= b'Vlx\x1a(\x8b\xe5\xac@\xce \xff\xeb^\xd9\x19\xef\xc6\x98\x82\xa3\x9a\x89\xc09{\xe0\xfbB\x1a\xac\x0b'
    
    private_client_key=''
    public_server_key=''
    id_client=0
    
    def encrypt_aes_easy(self, data, key):
        cipher=AES.new(key,AES.MODE_ECB)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        result=b64encode(ct_bytes).decode('utf-8')
        return result
        
    def encrypt_aes(self, data, key):
        '''
        Metodo che cifra con AES, dove data e key sono in bytes 
        '''
        cipher=AES.new(key,AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv':iv, 'ciphertext':ct})
        '''ritorna una stringa, impostata come json'''
        return result
    
    
    def tag_hmac_sha256(self,data, key):
        '''
        Semplice metodo per calcolare il tag con HMAC-Sha256, dove data in questo caso è una stringa
        '''
        h = HMAC.new(key, digestmod=SHA256)
        h.update(str.encode(data))
        tag=b64encode(h.digest()).decode('utf-8')
        #ritorna un tag a stringa
        return tag
        
    async def authentication_client(self):
        '''dal momento che non hanno scambiato i messaggi ancora la chiave simmetrica dovrebbe essere sconosciuta''' 
        endpoint=self.server_uri+"authentication"
        '''
        TO DO
        hello_str già pensato per inviare al server un json da poter ricercare in config.json del server dove
        verranno aggiunti le chiavi pubbliche dei sensori e attuatori
        '''
        hello_str= json.dumps({'type':'sensori', 'id':'sensore'+ str(self.id_client)})
        payload=json.dumps(hello_str).encode("utf-8") #byte
        response_hello=await self.send_get_request(endpoint,payload=payload)
        
        #il client ha ricevuto un messaggio dal server contenente la challenge
        response_string=json.loads(response_hello.payload.decode())
        response_json=json.loads(response_string)
        #assegnamo i campi che risulteranno stringhe
        enc_session_key=response_json["enc_session_key"]
        tag =response_json["tag"]
        ciphertext=response_json["ciphertext"]
        nonce=response_json["nonce"]
        private_key = RSA.import_key(open("./src/sensore/private_sensore.pem").read())
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
        
        #ora si cifra con la chiave pubblica del server e si manda la risposta
        psk=RSA.import_key(open("./src/sensore/public_server.pem").read())
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
        
        response_challenge=await self.send_post_request(endpoint,payload=payload)
        #TO DO 
        '''
        il server deve mandare sia la chiave del tag che del mac?
        '''
    
    
    async def send_get_request(self, endpoint,payload):
        '''
        Metodo che invia ad un endpoint una get con payload opzionale e restituisce la risposta alla richiesta, restiutisce None in caso di insuccesso
        '''
        try:
            protocol = await aiocoap.Context.create_client_context()
            if payload==None:
                request = aiocoap.Message(code=aiocoap.GET, uri=endpoint)
            else:
                request = Message(code=aiocoap.GET, uri=endpoint, payload=payload)
            logging.info(Fore.GREEN+"Richiesta inviata")

            response = await protocol.request(request).response
            print(response)
        except aiocoap.error.RequestTimedOut:
            logging.info(Fore.GREEN+"Richiesta al server CoAP scaduta")
            return None
        if response.code.is_successful():
            try:
                logging.info(Fore.GREEN+"Il server ha inviato una risposta valida")
                return response
            except ValueError:
                logging.info(Fore.GREEN+"Il server ha inviato una risposta non valida")
                return None
        else:
            logging.info(Fore.GREEN+f"Errore nella risposta del server: {response.code}")
            return None
    
    async def send_post_request(self, endpoint,payload):
        '''
        Metodo che invia ad un endpoint una post e restituisce la risposta alla richiesta, restiutisce None in caso di insuccesso
        '''
        try:
            protocol = await aiocoap.Context.create_client_context()
            request = Message(code=aiocoap.POST, uri=endpoint, payload=payload)
            logging.info(Fore.GREEN+"Richiesta inviata")

            response = await protocol.request(request).response
            print(response)
        except aiocoap.error.RequestTimedOut:
            logging.info(Fore.GREEN+"Richiesta al server CoAP scaduta")
            return None
        if response.code.is_successful():
            try:
                logging.info(Fore.GREEN+"Il server ha inviato una risposta valida")
                return response
            except ValueError:
                logging.info(Fore.GREEN+"Il server ha inviato una risposta non valida")
                return None
        else:
            logging.info(Fore.GREEN+f"Errore nella risposta del server: {response.code}")
            return None 
    
    async def data_request(self):
        data=self.get_field_value()
        endpoint=self.server_uri+"data"
        data=json.dumps(data).encode("utf-8")
        ct =json.loads(self.encrypt_aes(data, self.aes_key))
        tag= self.tag_hmac_sha256(ct['ciphertext'], self.hmac_key)
        result=json.dumps({'iv':ct['iv'], 'ciphertext':ct['ciphertext'], 'tag':tag})
        
        #AGGIUNTA QUI
        '''
        si usa result se si fa in modo di sniffare in chiaro i campi del json
        mentre result_cripto per nascondere anche quelli
        
        '''
        #result_cripto=self.encrypt_aes_easy(result.encode(), self.aes_key)
        #payload=json.dumps(result_cripto).encode("utf-8")
        
        ''''''
        payload=json.dumps(result).encode("utf-8")
        
        response=await self.send_get_request(endpoint,payload=payload)
    
        if response==None:
            logging.error("Something went wrong during server request handling")
       

def main():
    sensore= SensoreSecure()
    #sensore.print_info(os.path.abspath(__file__), psutil.net_if_addrs())
    print(sensore.max_iter)
    print(sensore.mode)   
    try:
        if  sensore.mode=="loop":
            iter=0
            loop=asyncio.get_event_loop()
            loop.run_until_complete(sensore.authentication_client())
            while True:
                time.sleep(sensore.time_unit)
                #Inserire qui i metodi di routine
                loop.run_until_complete(sensore.data_request())
                #time.sleep(sensore.time_interval)
                #loop.run_until_complete(sensore.health_request())

                #fine metodi di routine
                iter=iter+1
                if iter == sensore.max_iter:
                    exit("Max iters reached")
        else:
            print("Console mode:")
            print("-1 DataRequest\n-2 AL MOMENTO NIENTE\n-0 Exit")
            while True:
                run_command(sensore,input(">"))

    except Exception as ex:
        logging.error(ex)
        logging.error("Actuator cannot be instantiated")
        exit()


def run_command(sensore,cmd):
    loop=asyncio.get_event_loop()
    if cmd == '1':
        loop.run_until_complete(sensore.data_request())
    elif cmd == '2':
        print("CIAO PINO QUI NON ABBIAMO METODO")
    elif cmd == '0':
        exit("Bye")
    else:
        print("Comando non valido, repeat")


if __name__ == "__main__":
    asyncio.run(main())
    