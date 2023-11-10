import asyncio
import logging
import globalConstants as g
from server import Server
from aiocoap import resource
import aiocoap
import json
import signal

def close(signum, frame):
    
    handlers = logging.handlers[:]
    for handler in handlers:
        logging.removeHandler(handler)
        handler.close()
        logging.shutdown()
        exit()
    
async def main():
    try:
        s=Server()
        root = aiocoap.resource.Site()
        root.add_resource(('data',), DataResource(s))
        root.add_resource(('receive',), ReceiveState(s))
        root.add_resource(('heartbit',), Heartbit(s))
        logging.info(f"Resource tree OK")
        
        await aiocoap.Context.create_server_context(root,bind=[g.IP,g.PORT])
        logging.info(f"Avvio server aiocoap su %s e porta %s",g.IP, g.PORT)
        
        await asyncio.get_running_loop().create_future()
        
    
    except Exception as ex:
        logging.error("Server cannot be instantiated")
        logging.exception(ex)
        exit()

class DataResource(resource.Resource):      
    '''
    Riceve una get dal sensore e restituisce una:
    risposta con codice 2.05
    '''
    server=None
    def __init__(self,s):
        super().__init__()
        self.server=s    
    async def render_get(self, request):
        '''
        get request handling from sensors
        '''
        try: 
            request_json=json.loads(request.payload.decode())
            if not self.server.checkData(request_json):#:)
                logging.warning("Values not good")
                raise Exception("Bad values")
            
            self.server.addData(request)
            return aiocoap.Message(code=aiocoap.CHANGED)
        except ValueError as ve:
            logging.error("Exception in DataResource")
            logging.exception(ve)
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)
        except Exception as e:
            logging.exception(e)

class Heartbit(resource.Resource):
    def __init__(self,s):
        super().__init__()
        self.server=s

    '''
    Riceve delle get da attuatore e sensore per sapere se stann bene
    '''

    async def render_get(self,request):
        try:
            request_json=json.loads(request.payload.decode())
            ip=self.server.address_parser(request.remote.hostinfo)['address']
            self.server.timestamp[ip]=request_json['time_stamp']
            logging.info("HealtRequest Handling Success")
            return aiocoap.Message(code=aiocoap.CHANGED)

        except Exception:
            logging.error("HealtRequest Handling failed")
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)
            
        

class ReceiveState(resource.Resource):
    '''
    Riceve una get dall'attuatore e restituisce una:
    risposta con codice 2.05
    '''
    s=None
    def __init__(self,s):
        super().__init__()
        self.s=s

    async def render_get(self, request):
        '''
        get request handling from actuators
        '''
        try:
            ip="192.168.1.3"
            if not g.TESTING:
                ip=request.remote.ip
            #print(request.payload.decode())   
            comportamento=self.s.getBehave(ip)
            state={'state':comportamento}
            return aiocoap.Message(payload=json.dumps(state).encode("utf-8"))
        except ValueError:
            logging.error("ReceiveState Handling failed")
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)
    


        

'''
TO DO:
Sistema che ricevuto un dato e l'indirizzo IP effettui controlli base sui valori
come formato, segno etc poi valuta la coerenza del dato in relazione agli altri
dati disponibili con media comulativa.
WARNING NEL CASO IN CUI IL VALORE CORRENTE RICEVUTO SIA DISCORDE CON LA MEDIA CUMILATIVA
'''
    

'''
TO DO: Capire come gestire le politiche di istradamento e federazione
'''

'''
Console carina e coccolosa per le informazioni
'''

if __name__ == "__main__":
    signal.signal(signal.SIGINT, close)
    asyncio.run(main())
    
    