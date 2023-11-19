import json
import logging
import time
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
    
               

    def initConfig(self):
        '''
            Inizia il processo di digestione del file JSON aggiungendo alle varie strutture dati i file di configurazione
        '''
        try:
           time.sleep(3)
           print("Run .py file from the root folder")
           with open("../config/attuatore_config.json","rb") as x: #again problem
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



 