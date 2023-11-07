from base64 import b64encode
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

class SensoreSecure(Sensore):
    '''chiavi inizialmente messe qui per prova, 16 byte per AES, 32 per HMAC, da spostare il un file di configurazione poi'''
    aes_key= b'8\x14>V\xb3\xbc`\xa4\xd1\x18\xb4}\xf2\x89\xbf\xd7'
    hmac_key= b'Vlx\x1a(\x8b\xe5\xac@\xce \xff\xeb^\xd9\x19\xef\xc6\x98\x82\xa3\x9a\x89\xc09{\xe0\xfbB\x1a\xac\x0b'
    
    
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
    