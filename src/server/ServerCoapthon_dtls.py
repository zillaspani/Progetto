from coapthon import defines
from coapthon.server.coap import CoAP as CoapServer
from coapthon.resources.resource import Resource
import socket
from dtls.wrapper import wrap_server
import ssl
import logging
import json
import globalConstants as g
from Server import Server

class DataResource(Resource):      
    '''
    Riceve una get dal sensore e restituisce una:
    risposta con codice 2.05
    '''
    server=None
    def __init__(self,server,name="data_resource"):
        super(DataResource, self).__init__(name)
        self.server=server
        self.payload = "" #cio che viene dato all'esterno 
        self.resource_type = "rt1"
        self.content_type = "text/plain"
        self.interface_type = "if1"
   
    def render_POST(self, request):
        '''
        get request handling from sensors
        '''
        
        try:          
            request_json=json.loads(request.payload)
            if not self.server.checkData(request_json):#:)
                logging.warning("Values not good")
                raise Exception("Bad values")
            
            ip=request._source[0]
            self.server.addData(request_json,ip)
            self.code=defines.Codes.CHANGED.number
            self._sock
            return self
        except Exception as ex:
            logging.error("Exception in DataResource ")
            logging.exception(ex)
            self.code=defines.Codes.BAD_GATEWAY.number
            return self
 
 
class ReceiveState(Resource):
    server=None
    def __init__(self,server,name="receive_state_resource"):
        super(ReceiveState, self).__init__(name)
        self.server=server
        self.payload = "" #cio che viene dato all'esterno 
        self.resource_type = "rt1"
        self.content_type = "text/plain"
        self.interface_type = "if1"
         
    def render_GET(self, request):
        try:
           ip=request._source[0]
           comportamento=self.server.getBehave(ip)
           state={'state':comportamento}
           self.payload=json.dumps(state).encode("utf-8")
           self.code=defines.Codes.VALID.number
           return self
        except ValueError:
           logging.info("ReceiveState Handling failed")
           self.payload=""
           self.code=defines.Codes.BAD_GATEWAY.number
           return self
    
    
 
    
def ignore_listen_exception():
    return True

server=Server()
hostname= (g.IP,g.PORT)
'''
try:
    _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _sock = wrap_server(_sock,
                    cert_reqs=ssl.CERT_REQUIRED,
                    keyfile='../src/certificati/server.key',
                    certfile='../src/certificati/server-cert.pem',
                    ca_certs='../src/certificati/ca-cert.pem',
                    )
    _sock.bind(hostname)
    _sock.listen(0)
except Exception as e:
    logging.exception(e)
    logging.error("socket DTLS not started check certificates")
    exit()
'''

try:
    _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _sock = wrap_server(_sock,
                    cert_reqs=ssl.CERT_REQUIRED,
                    keyfile='../src/certificatiECDSA/server.key',
                    certfile='../src/certificatiECDSA/server-cert.pem',
                    ca_certs='../src/certificatiECDSA/ca-cert.pem',
                    #ciphers=g.CIPHER,
                    )
    _sock.bind(hostname)
    _sock.listen(0)
except Exception as e:
    logging.exception(e)
    logging.error("socket DTLS not started check certificates")
    exit()
    

s= CoapServer(hostname, sock = _sock,cb_ignore_listen_exception= ignore_listen_exception)
s.add_resource('data/',DataResource(server))
s.add_resource('receive/',ReceiveState(server))
logging.info("server started")
s.listen(1)
