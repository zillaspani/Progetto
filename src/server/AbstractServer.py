from abc import ABC, abstractmethod
import logging
import json
from aiocoap import resource
import aiocoap
import globalConstants as g
#from Utils import utils Sarò un coglione ma non riesco a farlo funzionare

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
        for c in self.config:
            if c["name"]==campo:
                valori=c["valori"]
                nomecampo=c["name"]
        for value in valori:
            print(value)
            self.values[nomecampo][value["name"]]["value"]=round(g.ALPHA*request_json[value["name"]]+(1-g.ALPHA)*self.values[nomecampo][value["name"]]["value"],2)
            self.values[nomecampo][value["name"]]["number"]=self.values[nomecampo][value["name"]]["number"]+1
            self.values[nomecampo][value["name"]]["history"].append(request_json[value["name"]])
            if len(self.values[nomecampo][value["name"]]["history"])>g.HISTORY:
                self.values[nomecampo][value["name"]]["history"].pop()
        print(self.values)
    
    def json_encoder(self,data):
        return json.dumps(data).encode("utf-8")
    
    def address_parser(self,host):
        pars=str(host).split(":")
        return {"address":pars[0],"port":pars[1]}

    class DataResource(resource.Resource):
        s=None
        
        '''
        Riceve una get dal sensore e restituisce una:
        risposta con codice 2.05
        '''
        
        def __init__(self,s):
            self.s=s
            
        def getData():
            pass
        
        def checkData(self, richiesta):
            '''
            check fitting of the data with statistical models (forse)
            '''
            return True
        
      
        async def render_get(self, request):
            '''
            get request handling from sensors
            '''
            try:
                print(request.payload.decode())    
                request_json=json.loads(request.payload.decode())
                if not self.checkData(request_json):#:)
                    logging.warning("Values not good")
                    raise Exception("Bad values")
               
                self.s.addData(request)
                return self.s.sendResponse(aiocoap.Message(code=aiocoap.CHANGED))
            except ValueError:
                print(aiocoap.BAD_REQUEST) # @Pirox forse va eliminato, non so vedi tu
                return self.s.sendResponse(aiocoap.Message(code=aiocoap.BAD_REQUEST))

    class Heartbit(aiocoap.resource.Resource):
        '''
        Riceve delle get da attuatore e sensore per sapere se stann bene
        '''

    def fromWhere(self,request):
        request.remote #ho perso la cazzo di istruzione da richiamare per ottenere l'ip del sender
        #vedi se vuoi unirla a get campo (da implementare) @ZILLASPANI#
        
    def get_expected_state(self,address):
        'TO FINISH'
        return None
    
    def get_address(self,request):
        return None

    class ReceiveState(aiocoap.resource.Resource):
        '''
        Riceve una get dal sensore e restituisce una:
        risposta con codice 2.05
        Attuatore deve inviare un messaggio confermabile
        '''
        s=None

        def __init__(self,s):
            self.s=s
        
        async def render_get(self, request):
            dati = {"state":True}
            ip=self.s.address_parser(request.remote.hostinfo)['address']
            payload=self.s.json_encoder(dati)
            #payload=utils.json_encoder(dati,"utf-8")
            return self.s.sendResponse(aiocoap.Message(payload=payload))

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