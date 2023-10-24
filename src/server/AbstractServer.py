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
    timestamp={}
    '''
    Struttura dati <ip,timestamp> contenente l'ultimo timestamp
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
        for campo in self.config:
            for attuatore in campo["attuatori"]:
                self.address[attuatore["ip"]]=campo["name"]

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

    def getBehave(self,address):
        '''
            Dato l'ip dell'attuatore restituisce il suo comportamento.
            Assunzione:
            Diamo importantanza all'umidità, dunque qualora le soglie di intervento fossero entrambe nella
            zona critica, si utilizza il comportamento definito per la temperatura.
        '''
        target=None
        campo=self.address[address]
        name=self.actuators[campo]["actuators"][address]
        temperatura=self.values[campo]["temperatura"]["value"]
        umidita=self.values[campo]["umidita"]["value"]
        interventoT=self.behavioral[campo]["temperatura"]["intervento"]
        interventoU=self.behavioral[campo]["umidita"]["intervento"]
        if(temperatura>=interventoT):
            target="temperatura"
        if(umidita>=interventoU):       #in accordo alle assunzioni, se l'umidità
            target="umidita"            #supera la soglia, si agirà sempre su questa indipendentemente
                                        #dalla temperatura
        if target==None:    
            return "trap"
        else:
            for comportamento in self.behavioral[campo][target]["comportamento"]:
                if name in comportamento:
                    return comportamento[name]
        
    def hardValues(self,campo,temp,umid):
        '''
        Metodo per hardcodare i valori di temperatura e umidità ai fini di testing
        '''
        self.values[campo]["temperatura"]["value"]=float(temp)
        self.values[campo]["umidita"]["value"]=float(umid)
   
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
                self.behavioral[nome][valore["name"]]["intervento"]=campo[valore["name"]]["intervento"]
                self.behavioral[nome][valore["name"]]["comportamento"]=[]
                for comportamento in campo[valore["name"]]["comportamento"]:
                    self.behavioral[nome][valore["name"]]["comportamento"].append(comportamento)

    def pretty_print(values):
        json_formatted_str = json.dumps(values, indent=2)
        print(json_formatted_str)
    
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

    def getTipo(self,request):
        '''
            ritorna il tipo di dispositivo, None se non esiste il dispositivo o il campo
        '''
        ip=self.address_parser(request.remote.hostinfo)['address']
        campo=self.getCampo(request)
        try:
            if ip in self.sensors[campo]['sensors']:
                logging.info(f"Il dispositivo {ip} è un sensore")
                return "sensor"
            if ip in self.actuators[campo]['actuators']:
                logging.info(f"Il dispositivo {ip} è un attuatore")
                return "attuatore"
            else:
                logging.info("Nessun dispositivo trovato")
                return None
        except KeyError as e:
            print("Il campo fornito non esiste")
            return None

    def getCampo(self,request):
        '''
            ritorna il campo an cui appartiene il sensore/attuatore
        '''
        ip=self.address_parser(request.remote.hostinfo)['address']
        campo=self.address[ip]
        return "campo0" #<- da cambiare con campo

    def json_encoder(self,data):
        return json.dumps(data).encode("utf-8")
    
    def address_parser(self,host):
        '''
        Dato un indirizzo "ip:port" restituisce una struttura accedibile per ip e porta
        '''
        pars=str(host).split(":")
        return {"address":pars[0],"port":pars[1]}

    def checkData(self, richiesta):
        '''
        check fitting of the data with statistical models (forse)
        '''
        return True

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

    @abstractmethod
    def sendResponse(self,response):
        pass
    
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
        
              
        async def render_get(self, request):
            '''
            get request handling from sensors
            '''
            try:
                print(request.payload.decode())    
                request_json=json.loads(request.payload.decode())
                if not self.s.checkData(request_json):#:)
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
        s=None

        def __init__(self,s):
            self.s=s

        async def render_get(self,request):
            try:
                request_json=json.loads(request.payload.decode())
                ip=self.s.address_parser(request.remote.hostinfo)['address']
                self.s.timestamp[ip]=request_json['time_stamp']


                return self.s.sendResponse(aiocoap.Message(code=aiocoap.CHANGED))

            except Exception:
                logging.info("HealtRequest Handling failed")
           

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
            '''
            get request handling from actuators
            '''
            try:
                
                #print(request.payload.decode())   
                
                testing_ip="192.168.1.3"
                comportamento=self.s.getBehave(testing_ip)
                print("Qui arriva "+comportamento)
                state={'state':comportamento}

                return self.s.sendResponse(aiocoap.Message(payload=json.dumps(state).encode("utf-8")))
            except ValueError:
                print(aiocoap.BAD_REQUEST) # @Pirox forse va eliminato, non so vedi tu
                return self.s.sendResponse(aiocoap.Message(code=aiocoap.BAD_REQUEST))
        


            

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
