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
from Sensore import Sensore



def ignore_write():
    return False

def ignore_read():
    return True


class SensoreCoapthon(Sensore):
    client=None
    def __init__(self,client=None):
        super().__init__()
        self.client=client
        
    def send_data(self):
        payload=self.get_field_value()
        self.client.post('data/',json.dumps(payload).encode('ascii'))
        
    def set_client(self,client):
        self.client=client
    
    
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
    '''
    try:
        sensore= SensoreCoapthon(client=None) 
        hostname= (sensore.address,sensore.port)
        _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _sock = wrap_client(_sock,
                    cert_reqs=ssl.CERT_REQUIRED,
                    ca_certs='../src/certs/t/ca-cert.pem',
                    ciphers='DHE-RSA-AES256-GCM-SHA384',
                    do_handshake_on_connect=True
                    )
        
        client = HelperClient(hostname,sock=_sock,cb_ignore_read_exception=ignore_read)
        sensore.set_client(client) 
    except Exception as ex:
        logging.exception(ex)
        logging.error("Sensore non inizializzato")
        client.close()
    '''
    cipher='ECDHE-RSA-AES256-GCM-SHA384'
    cont=0  
    while True:

        try:
            sensore= SensoreCoapthon(client=None)
            hostname= (sensore.address,sensore.port)
            socket=initClient(cipher) 
            client = HelperClient(hostname,sock=socket,cb_ignore_read_exception=ignore_read)
            sensore.set_client(client) 
        except Exception as ex:
            logging.exception(ex)
            logging.error("Sensore non inizializzato")
            client.close()

        try:  
            while True:
                time.sleep(sensore.time_unit)
                #Inserire qui i metodi di routine
                cont,behav=behavioral(cont)
                print("### Cont: "+str(cont)+" ###")
                if behav!=cipher:
                    logging.info("#########################################")
                    logging.info("Sensor change ciphersuite")
                    socket.close()
                    client.close()
                    cipher=behav
                    break
                sensore.send_data()

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
    
