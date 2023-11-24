import logging
import json
import globalConstants as g

class Server():
    config={}
    credentials=[]
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
        file = logging.FileHandler("server.log")
        file.setLevel(logging.DEBUG)
        file.setFormatter( logging.Formatter('%(asctime)s-%(levelname)s-%(message)s', datefmt=' %H:%M:%S')) 
        logging.basicConfig(level=logging.INFO, format='%(levelname)s-%(message)s', datefmt=' %H:%M:%S') 
        logging.getLogger().addHandler(file)
        logging.info("Loggin Starter")       
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

    def loadCred(self):
            '''
                Carica la struttura dati address con valori {psk:b"psk",client:"client"}]
            '''
            
            for campo in self.config:
                for sensore in campo["sensori"]:
                    record={}
                    record["psk"]=sensore["psk"].encode()
                    record["client_identity"]=sensore["name"].encode()
                    #record={"psk": sensore["psk"].encode(),"client_name": sensore["name"].encode()}
                    self.credentials.append(record)
            for campo in self.config:
                for attuatore in campo["attuatori"]:
                    record={}
                    record["psk"]=attuatore["psk"].encode()
                    record["client_identity"]=attuatore["name"].encode()
                    #record={"psk": sensore["psk"].encode(),"client_name": sensore["name"].encode()}
                    self.credentials.append(record)
            #print(self.credentials)

    
    def initConfig(self):
        '''
            Inizia il processo di digestione del file JSON aggiungendo alle varie strutture dati i file di configurazione
        '''
        try:
           
           with open("../config/server_config.json","rb") as x:
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
        try:
            self.loadCred()
        except Exception as err:
            print(err)
            logging.error("Impossibile caricare cred")
            exit()    

    def getBehave(self,address):
        '''
            Dato l'ip dell'attuatore restituisce il suo comportamento.
            Assunzione:
            Diamo importantanza all'umidità, dunque qualora le soglie di intervento fossero entrambe nella
            zona critica, si utilizza il comportamento definito per la temperatura. # UMIDITà?
        '''
        target=None
        campo=self.address[address]
        name=self.actuators[campo]["actuators"][address]
        temperatura=self.values[campo]["temperatura"]["value"]
        umidita=self.values[campo]["umidita"]["value"]
        interventoT=self.behavioral[campo]["temperatura"]["intervento"]
        interventoU=self.behavioral[campo]["umidita"]["intervento"]
            
        if(umidita>=interventoU):       #in accordo alle assunzioni, se l'umidità
            target="umidita"            #supera la soglia, si agirà sempre su questa indipendentemente
            
            for comportamento in self.behavioral[campo][target]["comportamento"]:
                if name in comportamento:
                    return comportamento[name]                        
        else:
            target="umidita"
            for comportamento in self.behavioral[campo][target]["comportamento"]:
                if name in comportamento:
                    return not comportamento[name]
                    
        if(temperatura>=interventoT):
            target="temperatura"
            for comportamento in self.behavioral[campo][target]["comportamento"]:
                if name in comportamento:
                    return comportamento[name]
        else:
            target="temperatura"
            for comportamento in self.behavioral[campo][target]["comportamento"]:
                if name in comportamento:
                    return comportamento[name]
             
        return "trap"
        
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

    def pretty_print(self,values):
        json_formatted_str = json.dumps(values, indent=3)
        print(json_formatted_str)
    
    def addData(self, request_json,ip):
        '''
        aggiunge i dati a values
        '''
        try:
            valori=None
            campo = self.getCampo(ip)
            for c in self.config:
                if c["name"]==campo:
                    valori=c["valori"]
                    nomecampo=c["name"]
            for value in valori:
                self.values[nomecampo][value["name"]]["value"]=round(g.ALPHA*request_json[value["name"]]+(1-g.ALPHA)*self.values[nomecampo][value["name"]]["value"],2)
                self.values[nomecampo][value["name"]]["number"]=self.values[nomecampo][value["name"]]["number"]+1
                self.values[nomecampo][value["name"]]["history"].append(request_json[value["name"]])
                if len(self.values[nomecampo][value["name"]]["history"])>g.HISTORY:
                    self.values[nomecampo][value["name"]]["history"].pop()    

        except Exception as e:
            logging.error("Problema con l'aggiunta dei dati")
            logging.exception(e)

    def getTipo(self,ip):
        '''
            ritorna il tipo di dispositivo, None se non esiste il dispositivo o il campo
        '''
        campo=self.getCampo(ip)
        try:
            if ip in self.sensors[campo]['sensors']:
                logging.info(f"Il dispositivo {ip} è un sensore")
                return "sensors"
            if ip in self.actuators[campo]['actuators']:
                logging.info(f"Il dispositivo {ip} è un attuatore")
                return "actuators"
            else:
                logging.info("Nessun dispositivo trovato")
                return None
        except KeyError as e:
            logging.error("Il campo fornito non esiste")
            return None

    def getCampo(self,ip):
        '''
            ritorna il campo an cui appartiene il sensore/attuatore
        '''
        try:
            campo=self.address[ip]
        except KeyError as e:
            logging.error("Ip errato/non in config")
            logging.error(e)
            return None
        return campo #<- da cambiare con campo

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

   