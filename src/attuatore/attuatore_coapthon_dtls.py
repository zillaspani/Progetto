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
                self.set_stato=response_json['state']
                logging.info("State Changed")
            else:
                logging.info("State Not Changed")
    
def main():
    try:
        attuatore= AttuatoreCoapthon(client=None)
        hostname= (attuatore.address,attuatore.port)
        _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _sock = wrap_client(_sock,
                    cert_reqs=ssl.CERT_REQUIRED,
                    keyfile= '../src/certificati/'+attuatore.name+'.key',
                    certfile= '../src/certificati/'+attuatore.name+'-cert.pem',
                    ca_certs='../src/certificati/ca-cert.pem',
                    ciphers="RSA",
                    do_handshake_on_connect=False)
    
        client = HelperClient(hostname,sock=_sock,cb_ignore_read_exception=ignore_read)
        attuatore.set_client(client) 
 
    
          
        while True:
            time.sleep(attuatore.time_unit)
            #Inserire qui i metodi di routine
            try:
                attuatore.state_request()
            except Exception as e:
                logging.exception(e)
                logging.exception("gestita male")               
          
    
    except Exception as ex:
        logging.error(ex)
        logging.error("Sensor cannot be instantiated")
        
        _sock.close()
        client.close()
        exit()
    
main()
    
