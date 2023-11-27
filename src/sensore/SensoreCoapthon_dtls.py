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

def _cb_ignore_read_exception():
    """
    In the CoAP client read method, different exceptions can arise from the DTLS stack. Depending on the type of exception, a
    continuation might not be possible, or a logging might be desirable. With this callback both needs can be satisfied.
    note: Default behaviour of CoAPthon without DTLS if no _cb_ignore_read_exception would be called is with "return False"
    :param exception: What happened inside the DTLS stack
    :param client: Reference to the running CoAP client
    :return: True if further processing should be done, False processing should be stopped
    """
    return False

def getCipherType():
    '''if len(sys.argv) != 1:
        print("Usage: python3 SensoreCoapthon_dtls.py <number>")
        print("1 per RSA ")
        print("1 per Crittografia a curve ellittiche ")
        print("1 per Crittografia a curve ellittiche con DH key exchange ")
        sys.exit(1)
    '''    
    inputC = int(sys.argv[1])

    while True:
        if inputC == 1:
            print("Hai scelto RSA")
            return "RSA"
        elif inputC == 2:
            print("Hai scelto Crittografia a curve ellittiche")
            return "EC"
        elif inputC == 3:
            print("Hai scelto Crittografia a curve ellittiche con DH key exchange")
            return "ECDH"
        else:
            print("Numero non valido")
            inputC = int(input("Inserisci un numero da 1 a 3 per effettuare la tua scelta: "))




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
    
def main():
    ciptherType=getCipherType()

    try:
        sensore= SensoreCoapthon(client=None) 
        hostname= (sensore.address,sensore.port)
        _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _sock = wrap_client(_sock,
                    cert_reqs=ssl.CERT_REQUIRED,
                    keyfile= '../src/certificati'+ciptherType+'/'+sensore.name+'.key',
                    certfile= '../src/certificati'+ciptherType+'/'+sensore.name+'-cert.pem',
                    ca_certs='../src/certificati'+ciptherType+'/ca-cert.pem',
                    do_handshake_on_connect=False)
        
        client = HelperClient(hostname,sock=_sock,cb_ignore_read_exception=ignore_read)
        sensore.set_client(client) 
    except Exception as ex:
        logging.exception(ex)
        logging.error("Sensore non inizializzato")
        client.close()
        
    try:
          
        while True:
            time.sleep(sensore.time_unit)
            #Inserire qui i metodi di routine
            
            sensore.send_data()
            print("dati inviati")
          
    
    except Exception as ex:
        logging.error(ex)
        logging.error("Sensor cannot be instantiated")
        
        _sock.close()
        client.close()
        exit()

    
main()
    
