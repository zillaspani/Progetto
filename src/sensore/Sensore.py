import logging
import json
import random
class Sensore:
    def __init__(self):
        self.initConfig()
        logging.basicConfig(level=logging.INFO)
        logging.getLogger("coap-sensor").setLevel(logging.DEBUG)
    

    def initConfig(self):
        '''
            Inizia il processo di digestione del file JSON aggiungendo alle varie strutture dati i file di configurazione
        '''
        try:
           print("Run .py file from the root folder")
           with open("src/sensore/config.json","rb") as x:
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
            self.temp_upper_bound=config['temperature_ub']
            self.temp_lower_bound=config['temperature_lb']
            self.humi_upper_bound=config['humidity_ub']
            self.humi_lower_bound=config['humidity_lb']
            self.roundig=config['rounding']
        except Exception as err:
            logging.error(err)
            logging.error("Loading behavior failed")
            exit()

    def get_field_value(self):
        humidity=random.uniform(self.humi_lower_bound,self.humi_upper_bound)
        temperature=random.uniform(self.temp_lower_bound,self.temp_upper_bound)
        return {"umidita":round(humidity, self.roundig),"temperatura":round(temperature,self.roundig)}


    def print_info(self, current_uri, network_interfaces):
        #current_uri = os.path.abspath(__file__)
        print( "URI del file sensore corrente:", current_uri)
        #network_interfaces = psutil.net_if_addrs() 
        #interface_name=psutil.net_if_addrs()
       