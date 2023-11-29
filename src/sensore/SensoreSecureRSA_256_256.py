from base64 import b64decode, b64encode
import os
import sys
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
from Crypto.Hash import HMAC, SHA256, SHA384
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Util.number import getPrime

class SensoreSecureRSA_256_256(Sensore):
    aes_key= b''
    hmac_key= b''
    
    
    def encrypt_aes(self, data, key):
        '''
        Metodo che cifra con AES, dove data e key sono in bytes,
        Va bene sia per chiavi di 16, sia di 32 byte
        '''
        cipher=AES.new(key,AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv':iv, 'ciphertext':ct})
        '''ritorna una stringa, impostata come json'''
        return result
    
    def digital_signature(self, data, path):
        private_key = RSA.import_key(open(path).read())
        hash_object = SHA256.new(data)
        # Generate the digital signature
        signature = pkcs1_15.new(private_key).sign(hash_object)
        #ritorna una stringa
        signature=b64encode(signature).decode('utf-8')
        return signature
    
    def tag_hmac_sha(self,data, key):
        '''
        Semplice metodo per calcolare il tag con HMAC-Sha384, dove data in questo caso è una stringa
        Va bene sia per chiavi di 16, sia di 32 byte
        '''
        h = HMAC.new(key, digestmod=SHA384)
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
        #path="./src/sensore/keys/private_sensore.pem"
        #signature=self.digital_signature(data,path)
        tag= self.tag_hmac_sha(ct['ciphertext'], self.hmac_key)
        result=json.dumps({'iv':ct['iv'], 'ciphertext':ct['ciphertext'], 'tag':tag})
        
        payload=json.dumps(result).encode("utf-8")
        
        response=await self.send_get_request(endpoint,payload=payload)
    
        if response==None:
            logging.error("Something went wrong during server request handling")
       
    async def handshake(self):
        public_key = RSA.import_key(open("../src/sensore/keys/public_sensore.pem").read())
        private_key = RSA.import_key(open("../src/sensore/keys/private_sensore.pem").read())
        endpoint=self.server_uri+"handshake"
        signature_byte = pkcs1_15.new(private_key).sign(SHA256.new(public_key.export_key('PEM')))
        encrypted_public_key_byte = self.public_server_key_encrypt(public_key.export_key("PEM"), "../src/sensore/keys/public_server.pem")
        signature_str= b64encode(signature_byte).decode('utf-8')
        epk_str = b64encode(encrypted_public_key_byte).decode('utf-8')
        result= json.dumps({'encrypted_key':epk_str, 'signature':signature_str})
        payload=json.dumps(result).encode("utf-8")
        response=await self.send_get_request(endpoint,payload=payload)
        #Ricevi la chiave pubblica Diffie-Hellman del server sia per aes che per h_mac
        response_string=json.loads(response.payload.decode())
        response_json=json.loads(response_string)
        #lavoro per aes
        p_aes=int(response_json['p_aes'])    
        key_string_aes=response_json['public_key_string_aes']
        key_bytes_aes=b64decode(key_string_aes)
        server_dh_key_aes = int.from_bytes(key_bytes_aes, 'big')
        g = 2
        private_dh_key_aes = get_random_bytes(32)
        public_dh_key_aes = pow(g, int.from_bytes(private_dh_key_aes, 'big'), p_aes)
        payload_to_byte_aes=b64encode(public_dh_key_aes.to_bytes((public_dh_key_aes.bit_length() + 7) // 8, 'big')).decode()
        #lavoro per hmac
        p_hmac=int(response_json['p_hmac'])    
        key_string_hmac=response_json['public_key_string_hmac']
        key_bytes_hmac=b64decode(key_string_hmac)
        server_dh_key_hmac = int.from_bytes(key_bytes_hmac, 'big')
        g = 2
        private_dh_key_hmac = get_random_bytes(32)
        public_dh_key_hmac = pow(g, int.from_bytes(private_dh_key_hmac, 'big'), p_hmac)
        payload_to_byte_hmac=b64encode(public_dh_key_hmac.to_bytes((public_dh_key_hmac.bit_length() + 7) // 8, 'big')).decode()
        #ora si invia
        result=json.dumps({'aes':payload_to_byte_aes, 'hmac':payload_to_byte_hmac})
        payload=json.dumps(result).encode("utf-8")
        response = await self.send_post_request(endpoint, payload=payload)
        # Calcola le chiavi segrete condivise utilizzando Diffie-Hellman
        shared_secret_aes = pow(server_dh_key_aes, int.from_bytes(private_dh_key_aes, 'big'), p_aes)
        shared_secret_bytes_aes = shared_secret_aes.to_bytes((shared_secret_aes.bit_length() + 7) // 8, 'big')
        print(sys.getsizeof(shared_secret_bytes_aes))
        shared_secret_hmac = pow(server_dh_key_hmac, int.from_bytes(private_dh_key_hmac, 'big'), p_hmac)
        shared_secret_bytes_hmac = shared_secret_hmac.to_bytes((shared_secret_hmac.bit_length() + 7) // 8, 'big')
        self.aes_key= shared_secret_bytes_aes
        self.hmac_key=shared_secret_bytes_hmac
        logging.info("Handshake completato correttamente, calcolo delle chiavi per AES e HMAC completato")
        if response==None:
            logging.error("Something went wrong during server request handling")

        
        
def main():
    sensore= SensoreSecureRSA_256_256()
    #sensore.print_info(os.path.abspath(__file__), psutil.net_if_addrs())
    print(sensore.max_iter)
    print(sensore.mode)   
    try:
        if  sensore.mode=="loop":
            iter=0
            loop=asyncio.get_event_loop()
            loop.run_until_complete(sensore.handshake())
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
        logging.error("Sensor cannot be instantiated")
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
    