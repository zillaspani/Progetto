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

cipher_h='ECDHE-ECDSA-AES256-GCM-SHA384'
cipher_l='ECDHE-ECDSA-AES128-GCM-SHA256'

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
                    ca_certs='../src/certs/ca-cert_ec.pem',
                    ciphers=cipher,
                    do_handshake_on_connect=True
                    )
        return _sock

def main():
    start_time=time.time()
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
    cipher=cipher_h
    #cont=0  
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
                #cont,behav=behavioral(cont)
                behav=behavioral(start_time)
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

def behavioral(start_time):
    TEST_TIME_M=1.5#durata in minuti
    END_TEST_M=3#durata in minuti
    now_time=time.time()
    delta=now_time-start_time
    SECONDS=60
    TEST_TIME=TEST_TIME_M*SECONDS
    END_TEST=END_TEST_M*SECONDS
    if delta < TEST_TIME:
        return cipher_h#h
    if delta > END_TEST:
        print("Test done, bye")
        exit()
    if delta > TEST_TIME:
        return cipher_h
    
    '''
    cont=cont+1
    if cont>=10 and cont <=15:
        if cont==15:
            return 0,'ECDHE-RSA-AES128-GCM-SHA256'
        return cont,'ECDHE-RSA-AES128-GCM-SHA256'
    if cont<10:
        return cont,'ECDHE-RSA-AES256-GCM-SHA384'
    '''
    
main()
    
