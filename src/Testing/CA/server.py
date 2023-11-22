import time
from coapthon import *
from coapthon import defines
from coapthon.server.coap import CoAP as CoapServer
from coapthon.resources.resource import Resource
import socket
from dtls.wrapper import wrap_server
import ssl
import datetime

class BasicResource(Resource):

    def __init__(self, name="Gianni", coap_server=None):

        super(BasicResource, self).__init__(name, coap_server, visible=True,
                                            observable=False, allow_children=True)
        self.payload = "Basic Resource" #cio che viene dato all'esterno 
        self.resource_type = "rt1"
        self.content_type = "text/plain"
        self.interface_type = "if1"
    
   
    def render_GET(self, request):
        #print('RICEVO GETTT')
        #NON MODIFICARE NIENTE NELLA GET, BRUTTO CANE
        #global server
        #server.notify(self)
        payload = datetime.datetime.now().strftime('%H:%M:%S').encode('ascii')
        self.payload = payload
        return self

    def render_PUT(self, request):
        self.edit_resource(request)
        #self.payload = request.payload.decode('UTF-8')
        return self

    def render_POST(self, request):
        res = self.init_resource(request, BasicResource())
        return res

    def render_DELETE(self, request):
        return True


def ignore_listen_exception():
    return True

bs = BasicResource()
hostname= ('127.0.0.1',5684)

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
s.add_resource('orologio/', BasicResource())
s.listen(1)
