from coapthon import defines
from coapthon.server.coap import CoAP as CoapServer
from coapthon.resources.resource import Resource
import socket
from dtls.wrapper import wrap_server
import ssl
import logging
import json
import globalConstants as g

"""class BasicResource(Resource):

    def __init__(self, name="Gianni", coap_server=None):

        super(BasicResource, self).__init__(name, coap_server, visible=True,
                                            observable=False, allow_children=True)
        self.payload = "Basic Resource" #cio che viene dato all'esterno 
        self.resource_type = "rt1"
        self.content_type = "text/plain"
        self.interface_type = "if1"
  
    def render_GET(self, request):

        #self.payload 
        return self

"""
class DataResource(Resource):      
    '''
    Riceve una get dal sensore e restituisce una:
    risposta con codice 2.05
    '''
    server=None
    def __init__(self,server=server,name="data_resource"):
        super(DataResource, self).__init__(name)
        self.server=server
        self.payload = "" #cio che viene dato all'esterno 
        self.resource_type = "rt1"
        self.content_type = "text/plain"
        self.interface_type = "if1"
    async def render_GET(self, request):
        '''
        get request handling from sensors
        '''
        try: 
            request_json=json.loads(request.payload.decode())
            if not self.server.checkData(request_json):#:)
                logging.warning("Values not good")
                raise Exception("Bad values")
            
            ip=self.server.address_parser(request.remote.hostinfo)['address']
            self.server.addData(request_json,ip)
            self.code=defines.Codes.CHANGED.number
            return self
        except ValueError:
            logging.error("Exception in DataResource "+ValueError)
            self.code=defines.Codes.BAD_GATEWAY.number
            return self


def ignore_listen_exception():
    return True

#bs = BasicResource()
hostname= (g.IP,g.PORT)

_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
_sock = wrap_server(_sock,
                    cert_reqs=ssl.CERT_REQUIRED,
                    keyfile='server.key',
                    certfile='server.pem',
                    ca_certs='ca.pem',
                    )
_sock.bind(hostname)
_sock.listen(0)

s= CoapServer(hostname, sock = _sock,cb_ignore_listen_exception= ignore_listen_exception)
s.add_resource('data/', DataResource())
s.listen(1)
