import sys
import time
from coapthon import defines
from coapthon.client.helperclient import HelperClient
from coapthon.server.coap import CoAP as CoapServer
from coapthon.resources.resource import Resource
import socket
from coapthon.messages.request import Request
from coapthon.messages.response import Response
from dtls.wrapper import wrap_client
import ssl
import logging
import json
from Attuatore import Attuatore

def ignore_write():
    return False

def ignore_read():
    return True

class AttuatoreCoapthon(Attuatore):
    client=None
    def __init__(self,client=None):
        super().__init__()
        self.client=client
    
    def set_client(self,client):
        self.client=client
        
    def send_data(self):
        risposta = self.client.get('receive/')
        return risposta
        
    def state_request(self):
        '''
        Invia una richiesta al server per conoscere in quale stato deve essere l'attuatore
        '''
        response=self.send_data()

        response_json=json.loads(response.payload)
        if response==None:
            logging.error("Something went wrong during server request handling")
        else:
            if response_json['state']!="trap":
                if self.stato != response_json['state']:
                    logging.info("State Changed")
                else:
                    logging.info("State Not Changed")
                self.set_stato=response_json['state']
               
            else:
                logging.info("State Not Changed")

def initClient(cipher):
        _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _sock = wrap_client(_sock,
                    cert_reqs=ssl.CERT_REQUIRED,
                    ca_certs='../src/certs/ca-cert.pem',
                    ciphers=cipher,
                    do_handshake_on_connect=True
                    )
        return _sock

def main():
    cipher='ECDHE-RSA-AES256-GCM-SHA384'
    cont=0 
    while True: 
        try:
            attuatore= AttuatoreCoapthon(client=None)
            hostname= (attuatore.address,attuatore.port)
            socket=initClient(cipher) 
            client = HelperClient(hostname,sock=socket,cb_ignore_read_exception=ignore_read)
            attuatore.set_client(client) 
        except Exception as ex:
            logging.exception(ex)
            logging.error("Attuatore non inizializzato")
            client.close()
        try:
            while True:
                time.sleep(attuatore.time_unit)
                #Inserire qui i metodi di routine
                cont,behav=behavioral(cont)
                if behav!=cipher:
                    logging.info("#########################################")
                    logging.info("Actuator change ciphersuite")
                    socket.close()
                    client.close()
                    cipher=behav
                    break
                attuatore.state_request()              
                
        except Exception as ex:
            logging.error(ex)
            logging.error("Sensor cannot be instantiated")
            socket.close()
            client.close()
            exit()

def behavioral(cont):
    cont=cont+1
    if cont>=10 and cont <=15:
        if cont==15:
            return 0,'ECDHE-RSA-AES128-GCM-SHA256'
        return cont,'ECDHE-RSA-AES128-GCM-SHA256'
    if cont<10:
        return cont,'ECDHE-RSA-AES256-GCM-SHA384'
    
main()
    
