import asyncio
import json
import logging


from colorama import Fore
from abc import abstractmethod



class Attuatore:
    def __init__(self):
        #self.server_uri = "coap://"+server_uri+"/"
        self.stato= False
        self.initConfig()
        logging.basicConfig(level=logging.INFO)
        logging.getLogger("coap-server").setLevel(logging.DEBUG)
    
    
    def get_stato(self):
        return self.stato
    
    def set_stato(self,stato):
        self.stato=stato
    


    #Metodo comune a tutti gli attuatori per stampare informazioni di debug 
    def print_info(self, current_uri, network_interfaces):
        #current_uri = os.path.abspath(__file__)
        print(Fore.GREEN+ "URI dell'attuatore corrente:", current_uri)
        print()
        #network_interfaces = psutil.net_if_addrs()
        interface_name = "eth0"
        ip_address = network_interfaces[interface_name][0].address
        print(f"Indirizzo IP dell'interfaccia {interface_name} dell'attuatore: {ip_address}")
        print()
    
    #Metodo astratto per implementare secondo quali politiche/librerie inviare i dati al server
    @abstractmethod
    def invia_richiesta(self):
        pass

    @abstractmethod
    def send_get_request(self,endpoint,payload):
        pass

    async def state_request(self):
        '''
        Invia una richiesta al server per conoscere in quale stato deve essere l'attuatore
        '''
        endpoint=self.server_uri+"receive"
        response=await self.send_get_request(endpoint,None)
        if response!=None:
            payload=json.loads(response.payload.decode())
            
            print(payload['state'])

    async def health_request(self):
        '''
        Invia una richiesta al server per far sapere che è vivo
        '''
        endpoint=self.server_uri+"heartbit"
        self.send_get_request(endpoint,"Alive")
       

    def initConfig(self):
        '''
            Inizia il processo di digestione del file JSON aggiungendo alle varie strutture dati i file di configurazione
        '''
        try:
           print("Run .py file from the root folder")
           with open("src/attuatore/config.json","rb") as x: #again problem
                x=x.read()
                config=json.loads(x)
        except Exception as err:
            logging.error(err)
            logging.error("File config.json not present in root folder o reading problem")
            exit("Error opening JSON")    
        
        try:
            self.server_uri="coap://"+config['uri']+"/"
            self.mode=config['behav']
            self.time_unit=config['t_unit']
            self.time_interval=config['t_interval']
            self.max_iter=config['max_iter']

        except Exception as err:
            logging.error(err)
            logging.error("Loading behavior failed")
            exit()



 