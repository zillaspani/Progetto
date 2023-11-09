import time
import aiocoap
import asyncio
import json
import logging
from aiocoap import *
from Sensore import Sensore

class SensoreDtls(Sensore):
    
    
    protocol=None
        
    async def start(self):
        self.protocol = await aiocoap.Context.create_client_context(transports=['tinydtls'])
        client_cr={'coaps://127.0.0.1/data': {'dtls': {'psk': b'secretPSK','client-identity': b'client_Identity',}}}
        self.protocol.client_credentials.load_from_dict(client_cr)
        
    async def send_get_request(self, endpoint,payload):
        '''
        Metodo che invia ad un endpoint una get con payload opzionale e restituisce la risposta alla richiesta, restiutisce None in caso di insuccesso
        '''
        try:
            if payload==None:
                request = aiocoap.Message(code=aiocoap.GET, uri=endpoint)
            else:
                request = aiocoap.Message(code=aiocoap.GET, uri=endpoint,payload=payload)
            logging.info("Richiesta inviata")

            response = await self.protocol.request(request).response
            logging.info(response)
        except aiocoap.error.RequestTimedOut:
            logging.info("Richiesta al server CoAP scaduta")
            return None
        if response.code.is_successful():
            try:
                logging.info("Il server ha inviato una risposta valida")
                return response
            except ValueError:
                logging.info("Il server ha inviato una risposta non valida")
                return None
        else:
            logging.info(f"Errore nella risposta del server: {response.code}")
            return None
    
    async def data_request(self):
        data=self.get_field_value()
        endpoint=self.server_uri+"data"
        payload=json.dumps(data).encode("utf-8")
        response=await self.send_get_request(endpoint,payload=payload)
        if response==None:
            logging.error("Something went wrong during server request handling")
    
    """
    async def health_request(self):
        '''
        Invia una richiesta al server per far sapere che è vivo
        '''
        time_stamp={"time_stamp":str(time.time())}
        payload=json.dumps(time_stamp).encode("utf-8")
        endpoint=self.server_uri+"heartbit"

        response=await self.send_get_request(endpoint,payload=payload)
        if response==None:
            logging.error("Something went wrong during server request handling")
    
    """
    
def main():
    sensore=SensoreDtls()
    loop=asyncio.get_event_loop()
    loop.run_until_complete(sensore.start())
    ###CAMBIA QUI, MI SECCAVA A PRENDERE UN RIFERIMENTO MA DEVI FARE SENSORE.address o simili e salvari in sensore l'address
    sensore.server_uri="coaps://"+"127.0.0.1"+"/"
    #sensore.print_info(os.path.abspath(__file__), psutil.net_if_addrs())
    print(sensore.max_iter)
    print(sensore.mode)   
    try:
        if  sensore.mode=="loop":
            iter=0
            while True:
                time.sleep(sensore.time_unit)
                #Inserire qui i metodi di routine
                loop.run_until_complete(sensore.data_request())
                time.sleep(sensore.time_interval)
                #loop.run_until_complete(sensore.health_request())

                #fine metodi di routine
                iter=iter+1
                if iter == sensore.max_iter:
                    exit("Max iters reached")
        else:
            print("Console mode:")
            print("-1 DataRequest\n-2 AL MOMENTO NIENTE\n-0 Exit")
            while True:
                run_command(sensore,input(">"),loop)

    except Exception as ex:
        logging.error(ex)
        logging.error("Actuator cannot be instantiated")
        exit()


def run_command(sensore,cmd,loop):
    
    if cmd == '1':
        loop.run_until_complete(sensore.data_request())
    elif cmd == '2':
        #loop.run_until_complete(sensore.health_request())
        pass
    elif cmd == '0':
        exit("Bye")
    else:
        print("Comando non valido, repeat")


if __name__ == "__main__":
    asyncio.run(main())