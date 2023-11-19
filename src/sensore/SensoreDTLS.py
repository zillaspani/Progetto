import time
import aiocoap
import asyncio
import json
import logging
from aiocoap import *
from Sensore import Sensore


class SensoreDTLS(Sensore):
    
    protocol=None
        
    async def start(self):
        self.protocol = await aiocoap.Context.create_client_context(transports=['tinydtls'])
        client_cr={'coaps://127.0.0.1/data': {'dtls': {'psk': self.psk.encode(),'client-identity':self.name.encode()}}}
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
            #logging.info(response)
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
        while True:
            time.sleep(self.time_interval)
            data=self.get_field_value()
            endpoint=self.server_uri+"data"
            payload=json.dumps(data).encode("utf-8")
            response=await self.send_get_request(endpoint,payload=payload)
            if response==None:
                logging.error("Something went wrong during server request handling")
    

def main():
    sensore=SensoreDTLS()
    loop=asyncio.get_event_loop()
    loop.run_until_complete(sensore.start())
    sensore.server_uri="coaps://"+sensore.address+"/"
    loop.run_until_complete(sensore.data_request())
           

if __name__ == "__main__":
    asyncio.run(main())