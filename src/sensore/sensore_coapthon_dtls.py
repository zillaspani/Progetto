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

from sensore.Sensore import Sensore
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
'''req = Request()
req.code = defines.Codes.GET.number
req.uri_path = "nicola/"
req.type = defines.Types["CON"]
req.destination = hostname
x= client.send_request(req) #questo e' un modo di fare una get, a mano. 
'''

class SensoreAiocoap(Sensore):
    client=None
    def __init__(self,client=None):
        super().__init__()
        self.client=client
        
    def sendData(self):
        risposta = self.client.get('data/',payload=Sensore.get_field_value())
        print(risposta)
        pass
    
def main():
    
    hostname= (sensore.address,5684)
    _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _sock = wrap_client(_sock,
                cert_reqs=ssl.CERT_REQUIRED,
                keyfile= 'client.key',
                certfile= 'client.pem',
                ca_certs='ca.pem',
                ciphers="RSA",
                do_handshake_on_connect=False)

    client = HelperClient(hostname,sock=_sock,cb_ignore_read_exception=ignore_read)
    sensore= SensoreAiocoap(client=client) 
    try:
          
        while True:
            time.sleep(sensore.time_unit)
            #Inserire qui i metodi di routine
            sensore.send_data()
          
    
    except Exception as ex:
        logging.error(ex)
        logging.error("Sensor cannot be instantiated")
        
        _sock.close()
        client.close()
        exit()
    
    
