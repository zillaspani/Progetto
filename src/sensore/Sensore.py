import logging
import json
import random
import time
import setproctitle

class Sensore:
    stop=False
    x=None
    process=None
    def __init__(self):
        try:
            #setproctitle.getproctitle()
            self.initConfig()
            setproctitle.setproctitle(self.name)
            logging.basicConfig(level=logging.INFO)
            logging.getLogger("coap-sensor").setLevel(logging.DEBUG)
        except:
            exit("Errore durante l'init")
        
    def initConfig(self):
        '''
            Inizia il processo di digestione del file JSON aggiungendo alle varie strutture dati i file di configurazione
        '''
        try:
           with open("../config/sensore_config.json","rb") as x:
                x=x.read()
                config=json.loads(x)
        except Exception as err:
            logging.error(err)
            logging.error("File config.json not present in root folder o reading problem")
            exit("Error opening JSON")    
        
        try:
            self.port=config['port']
            self.address=config['address']
            self.server_uri="coap://"+config['uri']+"/"
            self.name=config['name']
            self.cipher=config['cipher']
            self.mode=config['behav']
            self.time_unit=config['t_unit']
            self.time_interval=config['t_interval']
            self.max_iter=config['max_iter']
            self.temp_upper_bound=config['temperature_ub']
            self.temp_lower_bound=config['temperature_lb']
            self.humi_upper_bound=config['humidity_ub']
            self.humi_lower_bound=config['humidity_lb']
            self.roundig=config['rounding']
            self.TEST_TIME_M=config['TEST_TIME_M']
            self.END_TEST_M=config['END_TEST_M']
        except Exception as err:
            logging.error(err)
            logging.error("Loading behavior failed")
            exit()
        try:
                self.psk=config['psk']
        except:
            logging.info("Non è presente il campo PSK, DTLS non disponibile.")

    def get_field_value(self):
        humidity=random.uniform(self.humi_lower_bound,self.humi_upper_bound)
        temperature=random.uniform(self.temp_lower_bound,self.temp_upper_bound)
        return {"umidita":round(humidity, self.roundig),"temperatura":round(temperature,self.roundig)}
    
    def test(self,start_time):
        now_time=time.time()
        delta=now_time-start_time
        SECONDS=60
        TEST_TIME=self.TEST_TIME_M*SECONDS
        END_TEST=self.END_TEST_M*SECONDS
        if delta < TEST_TIME:
            pass
        if delta > END_TEST:
            print("Test done, bye")
            exit()
        if delta > TEST_TIME:
            pass
    