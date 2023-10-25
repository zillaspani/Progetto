import json
import logging
from colorama import Fore

class Attuatore:
    def __init__(self):
        self.stato= False
        self.initConfig()
        logging.basicConfig(level=logging.INFO)
        logging.getLogger("coap-actuator").setLevel(logging.DEBUG)
    
    
    def get_stato(self):
        return self.stato
    
    def set_stato(self,stato):
        self.stato=stato
    


    
    def print_info(self, current_uri, network_interfaces):
        '''
        Fantasiaaa
        '''
        #current_uri = os.path.abspath(__file__)
        print(Fore.GREEN+ "URI dell'attuatore corrente:", current_uri)
        print()
        #network_interfaces = psutil.net_if_addrs()
        interface_name = "eth0"
        ip_address = network_interfaces[interface_name][0].address
        print(f"Indirizzo IP dell'interfaccia {interface_name} dell'attuatore: {ip_address}")
               

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



 