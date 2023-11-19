import time
import json
import asyncio
import aiocoap
import logging
from aiocoap import *
from Attuatore import Attuatore


class AttuatoreDTLS(Attuatore):
    protocol=None
    async def start(self):
        self.protocol = await aiocoap.Context.create_client_context(transports=['tinydtls'])
        client_cr={'coaps://127.0.0.1/*': {'dtls': {'psk': self.psk.encode(),'client-identity':self.name.encode()}}}
        self.protocol.client_credentials.load_from_dict(client_cr)
    
    async def state_request(self):
      
        while True:
            time.sleep(self.time_unit)
       
            endpoint=self.server_uri+"receive"
            response=await self.send_get_request(endpoint,None)

            response_json=json.loads(response.payload.decode())
            if response==None:
                logging.error("Something went wrong during server request handling")
            else:
                if response_json['state']!="trap": #@pirox a me piacerebbe che quando non si deve fare nulla la response sia trap
                    self.set_stato=response_json['state']
                    logging.info("State Changed")
                else:
                    logging.info("State Not Changed")
        
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


def main():
    attuatore= AttuatoreDTLS()
    asyncio.get_event_loop().run_until_complete(attuatore.start())
    attuatore.server_uri="coaps://"+attuatore.address+"/"  
    loop=asyncio.get_event_loop()
    loop.run_until_complete(attuatore.state_request())

          
if __name__ == "__main__":
    asyncio.run(main())