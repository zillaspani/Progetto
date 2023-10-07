from abc import ABC, abstractmethod
import asyncio
import aiocoap.resource as resource
import aiocoap
import logging
import socket
import json 
class AbstractServer(ABC):
    behavioral={}
    values={}
    config={}
    def __init__(self):
        root = resource.Site()
        root.add_resource(('data',), self.DataResource())
        root.add_resource(('receive',), self.ReceiveState())
        asyncio.get_event_loop().run_until_complete(aiocoap.Context.create_server_context(root))
        ip_address = socket.gethostbyname(socket.gethostname)
        logging.info(f"Avvio server aiocoap su %s ",ip_address)
        asyncio.get_event_loop().run_forever()
        #to do: metodo 
        with open("config.json","r") as x:
            self.config=json.loads(x)
            self.behavioral=self.config[]
        logging("config.json loaded!")

    class DataResource(resource.Resource):
        
        '''
        Riceve una get dal sensore e restituisce una:
        risposta con codice 2.05
        '''
            
        def getData():
            pass
        
        def checkData(self, richiesta):
            '''
            check fitting of the data with statistical models (forse)
            '''
            return True
        
        def registerData(self, richiesta):
            '''
            aggiunge i dati a values
            '''
            
        @abstractmethod
        def sendResponse(self,response):
            pass

        async def render_get(self, request):
            '''
            get request handling from sensors
            '''
            try:    
                request_json=json.loads(request.payload.decode())
                if self.checkData(self, request):#!!PIROX!! Self solo nella dichiarazione del metodo, elimaniamo o ti serve?
                    logging.warning("values not good")
                    raise Exception("Bad values")
                self.registerData(request_json)
                logging.info()
                self.sendResponse(aiocoap.Message(code=aiocoap.CHANGED))
            except ValueError:
                print(aiocoap.BAD_REQUEST)
                self.sendResponse(aiocoap.Message(code=aiocoap.BAD_REQUEST))

    class Heartbit(resource.Resource):
        '''
        Riceve delle get da attuatore e sensore per sapere se stann bene
        '''

    def fromWhere(self,request):
        request.remote #ho perso la cazzo di istruzione da richiamare per ottenere l'ip del sender
        


    class ReceiveState(resource.Resource):
        '''
            get request handling from sensors
        '''
        async def render_get(self, request):
        #Prima cosa si vede capire da dove proviene la richiesta
            field=fromWhere(request)

        '''
        Riceve una get dall'attuatore e restituisce una:
        risposta con codice 2.05
        Funzione che invia nel body della risposta una informazione.
        Attuatore deve inviare un messaggio confermabile
        '''

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


