from abc import ABC, abstractmethod
import asyncio
import aiocoap.resource as resource
import aiocoap
import logging
import socket
import json
import globalConstants as g

class AbstractServer(ABC):
    behavioral={}
    values={}
    config={}
    address={}

    def __init__(self):
        #to do: metodo 
        self.initConfig() 
        logging("config.json loaded!")
        root = resource.Site()
        root.add_resource(('data',), self.DataResource())
        root.add_resource(('receive',), self.ReceiveState())
        asyncio.get_event_loop().run_until_complete(aiocoap.Context.create_server_context(root))
        ip_address = socket.gethostbyname(socket.gethostname)
        logging.info(f"Avvio server aiocoap su %s ",ip_address)
        asyncio.get_event_loop().run_forever()    
    
    def addressConfig(self):
        '''
            Carica la struttura dati address con valori [ip]->[campo]
        '''
        for campo in self.config:
            for sensore in campo["sensori"]:
                self.address[sensore["ip"]]=campo["nome"]

    def initConfig(self):
        '''
            Inizia il processo di digestione del file JSON aggiungendo alle varie strutture dati i file di configurazione
        '''
        with open("config.json","r") as x:
            self.config=json.loads(x)
        for campo in self.config:
            valori=self.config[campo]["valori"]
            for valore in valori:
                self.values[campo][valore]={}
        self.loadBehave()
        self.addressConfig()

    def loadBehave(self):
        '''
            carica i comportamenti per ogni campo come 
        '''
        for campo in self.config["campi"]:
            valori=self.config[campo]["valori"]
            for valore in valori:
                nome=campo["nome"]
                self.behavioral[nome][valore]=campo[valore]["COMPORTAMENTO"]
        
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
        
        def getCampo(self,richiesta):
            '''
                ritorna il campo an cui appartiene il sensore/attuatore
            '''

            
        def addData(self, request):
            '''
            aggiunge i dati a values
            '''
            campo = self.getCampo(request)
            request_json=json.loads(request.payload.decode())
            valori=self.config[campo]["valori"]
            for value in valori:
                self.values[value]=g.ALPHA*request_json[value]+(1-g.ALPHA)*self.values[value]

            
        @abstractmethod
        def sendResponse(self,response):
            pass

        async def render_get(self, request):
            '''
            get request handling from sensors
            '''
            try:    
                request_json=json.loads(request.payload.decode())
                if self.checkData(request_json):#:)
                    logging.warning("values not good")
                    raise Exception("Bad values")
                self.addData(request )
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
        #vedi se vuoi unirla a get campo (da implementare) @ZILLASPANI#
        


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


