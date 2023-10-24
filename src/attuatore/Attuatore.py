import asyncio
import json
import logging
import time

from colorama import Fore
from abc import abstractmethod

'''
CON = 0
NON = 1
ACK = 2
RST = 3
'''

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

        response_json=json.loads(response.payload.decode())
        if response_json['state']!="trap": #@pirox a me piacerebbe che quando non si deve fare nulla la response sia trap
            self.set_stato=response_json['state']
            logging.info("State Changed")
        else:
            logging.info("State Not Changed")
            

        

    async def health_request(self):
        '''
        Invia una richiesta al server per far sapere che è vivo
        '''
        time_stamp={"time_stamp":str(time.time())}
        payload=json.dumps(time_stamp).encode("utf-8")
        endpoint=self.server_uri+"heartbit"

        response=await self.send_get_request(endpoint,payload=payload)
        
        print(response)
       

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



 