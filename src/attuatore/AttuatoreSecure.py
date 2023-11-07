from base64 import b64decode, b64encode
import os
import time
import psutil
import json
import asyncio
import aiocoap
import logging
from aiocoap import *
from colorama import Fore
from Attuatore import Attuatore
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad


class AttuatoreSecure(Attuatore):
    '''chiavi inizialmente messe qui per prova, 16 byte per AES, 32 per HMAC, da spostare il un file di configurazione poi'''
    aes_key=b'u\xa3\\\x96\x08\x8e\xd3jc\x0f\xdbq3\xc4\x1d\xde'
    hmac_key=b'\xcbV\xfdU\xf5\xcf\xcb\xcczI\xa6p\xaf\xe8=\x18\x18\x17`\xe4\xb0\xaf$a\x0c/\xc8\xach\xda\x92\xc2'

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
        print(response_json)   
        if response==None:
            logging.error("Something went wrong during server request handling")
        else:
            if response_json['state']!="trap": #@pirox a me piacerebbe che quando non si deve fare nulla la response sia trap
                self.set_stato=response_json['state']
                logging.info("State Changed")
            else:
                logging.info("State Not Changed")
            

    async def health_request(self):
        '''
        Invia una richiesta al server per far sapere che è vivo
        '''
        time_stamp={"time_stamp":str(time.time())}
        payload=json.dumps(time_stamp).encode("utf-8")
        endpoint=self.server_uri+"heartbit"

        response=await self.send_get_request(endpoint,payload=payload)
        if response==None:
            logging.error("Something went wrong during server request handling")
        
        
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
            logging.info(Fore.GREEN+"Richiesta inviata")

            response = await protocol.request(request).response
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


def main():
    attuatore= AttuatoreSecure()
    attuatore.print_info(os.path.abspath(__file__), psutil.net_if_addrs())
    print(attuatore.max_iter)
    print(attuatore.mode)   
    try:
        if  attuatore.mode=="loop":
            iter=0
            loop=asyncio.get_event_loop()
            while True:
                time.sleep(attuatore.time_unit)
                #Inserire qui i metodi di routine
                loop.run_until_complete(attuatore.state_request())
                #time.sleep(attuatore.time_interval)
                #loop.run_until_complete(attuatore.health_request())

                #fine metodi di routine
                iter=iter+1
                if iter == attuatore.max_iter:
                    exit("Max iters reached")
        else:
            print("Console mode:")
            print("-1 StateRequest\n-2 HealthRequest\n-0 Exit")
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
    elif cmd == '2':
        loop.run_until_complete(attuatore.health_request())
    elif cmd == '0':
        exit("Bye")
    else:
        print("Comando non valido, repeat")


if __name__ == "__main__":
    asyncio.run(main())