from abc import ABC, abstractmethod
import logging
import json
from aiocoap import resource
import aiocoap
import globalConstants as g

class AbstractServer(ABC):
    config={}
    behavioral={}
    '''
    struttura dati json per comportamenti
    campi{
        valore0{
            intervento: 0.0 soglia di intervento o cambio comporamento attuatori descritti
            comportamento= [
                --insieme di regole
            ]
            } ---- per esempio temperatura
        valore1{
            come sopra
            } ---- per esempio umidità
        
    }
    '''
    values={}
    '''
    stuttura che mantiene valori, numero dati arrivati e storia
    '''
    address={}
    '''
    struttra che mantiene gli indirizzi ip e i campi a cui sono associati
    '''
    sensors={}
    '''
    indirizzi ip e sensori, numero divisi per campo
    '''
    actuators={}
    '''
    indirizzi ip e sensori, numero divisi per campo
    '''
    
    def __init__(self):
        #to do: metodo
        logging.basicConfig(level=logging.INFO)
        logging.getLogger("coap-server").setLevel(logging.DEBUG) 
        try: 
            self.initConfig()
        except Exception as error:
            logging.error(error)
            logging.error("config.json not loaded")
            exit("Server cannot work if JSON file is not right loaded")
             
        logging.info("config.json loaded!")
        
    def loadSensorsAndActuators(self):
        '''
            Carica strutture dati sensori ed attuatori
        '''
        for campo in self.config:
            self.sensors[campo["name"]]={}
            self.actuators[campo["name"]]={}
            self.sensors[campo["name"]]["number"]=len(campo["sensori"])
            self.sensors[campo["name"]]["sensors"]={}
            self.actuators[campo["name"]]["number"]=len(campo["attuatori"])
            self.actuators[campo["name"]]["actuators"]={}
            for sensore in campo["sensori"]:
                self.sensors[campo["name"]]["sensors"][sensore["ip"]]=sensore["name"]
            for attuatore in campo["attuatori"]:
                self.actuators[campo["name"]]["actuators"][attuatore["ip"]]=attuatore["name"]
   
        
    def addressConfig(self):
        '''
            Carica la struttura dati address con valori [ip]->[campo]
        '''
        for campo in self.config:
            for sensore in campo["sensori"]:
                self.address[sensore["ip"]]=campo["name"]

    def initConfig(self):
        '''
            Inizia il processo di digestione del file JSON aggiungendo alle varie strutture dati i file di configurazione
        '''
        try:

           print("Run .py file from the root folder")

           with open("config.json","rb") as x:
                x=x.read()
                self.config=json.loads(x)["campi"]
        except Exception as err:
            logging.error(err)
            logging.error("File config.json not present in root folder o reading problem")
            exit("Error opening JSON")    
        for campo in self.config:
            self.values[campo["name"]]={}
            valori=campo["valori"]
            for valore in valori:
                self.values[campo["name"]][valore["name"]]={}
                self.values[campo["name"]][valore["name"]]["value"]=0.0
                self.values[campo["name"]][valore["name"]]["history"]=[]
                self.values[campo["name"]][valore["name"]]["number"]=0
        try:
            self.loadBehave()
        except Exception as err:
            logging.error(err)
            logging.error("Loading behavior failed")
            exit()
        try:
            self.addressConfig()
        except:
            logging.error("Loading ip address failed")
            exit()
        try:
            pass
            self.loadSensorsAndActuators()
        except Exception as err:
            logging.error(err)
            logging.error("Loading sensors and/or actuators failed")
            exit()
            
        
    def loadBehave(self):
        '''
            carica i comportamenti per ogni campo come 
        '''
        for campo in self.config:
            valori=campo["valori"]
            nome=campo["name"]
            self.behavioral[nome]={}
            for valore in valori:
                self.behavioral[nome][valore["name"]]={}
                self.behavioral[nome][valore["name"]]["intervento"]=campo[valore["name"]]["INTERVENTO"]
                self.behavioral[nome][valore["name"]]["comportamento"]=[]
                for comportamento in campo[valore["name"]]["COMPORTAMENTO"]:
                    self.behavioral[nome][valore["name"]]["comportamento"].append(comportamento)
    @abstractmethod
    def sendResponse(self,response):
        pass
    
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
            return "campo0" #<- da cambiare

            
        def addData(self, request):
            '''
            aggiunge i dati a values
            '''
            campo = self.getCampo(request)
            request_json=json.loads(request.payload.decode())
            valori=self.config[campo]["valori"]
            for value in valori:
                self.values[value["name"]]["value"]=g.ALPHA*request_json[value["name"]]+(1-g.ALPHA)*self.values[value]
                self.values[value["name"]]["number"]=self.values[value]["number"]+1
                self.values[value["name"]]["history"].append(value["name"])
                if len(self.values[value["name"]]["history"])>g.HISTORY:
                    self.values[value["name"]]["history"].pop()

        async def render_get(self, request):
            '''
            get request handling from sensors
            '''
            try:
                print(request.payload.decode())    
                request_json=json.loads(request.payload.decode())
                if self.checkData(request_json):#:)
                    logging.warning("Values not good")
                    raise Exception("Bad values")
                self.addData(request)
                logging.info()
                return self.sendResponse(aiocoap.Message(code=aiocoap.CHANGED))
            except ValueError:
                print(aiocoap.BAD_REQUEST)
                return self.sendResponse(aiocoap.Message(code=aiocoap.BAD_REQUEST))

    class Heartbit(aiocoap.resource.Resource):
        '''
        Riceve delle get da attuatore e sensore per sapere se stann bene
        '''

    def fromWhere(self,request):
        request.remote #ho perso la cazzo di istruzione da richiamare per ottenere l'ip del sender
        #vedi se vuoi unirla a get campo (da implementare) @ZILLASPANI#
        


    class ReceiveState(aiocoap.resource.Resource):
        '''
            get request handling from sensors
        '''

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


    class DummyResource(resource.Resource):
        async def render_get(self, request):
            logging.info("Qui arriva")
            text = ["Request came from %s." % request.remote.hostinfo]
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            text.append("The server address used %s." % request.remote.hostinfo_local)

            return aiocoap.Message(content_format=0, payload="CCC\n".join(text).encode('utf8'))