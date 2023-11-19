import time
import json
import asyncio
import aiocoap
import logging
from aiocoap import *
from Attuatore import Attuatore


class AttuatoreAiocoap(Attuatore):

    async def state_request(self):
        '''
        Invia una richiesta al server per conoscere in quale stato deve essere l'attuatore
        '''
        endpoint=self.server_uri+"receive"
        response=await self.send_get_request(endpoint)

        response_json=json.loads(response.payload.decode())
        if response==None:
            logging.error("Something went wrong during server request handling")
        else:
            if response_json['state']!="trap": 
                self.set_stato=response_json['state']
                logging.info("State Changed")
            else:
                logging.info("State Not Changed")
                            
    async def send_get_request(self, endpoint):
        '''
        Metodo che invia ad un endpoint una get con payload opzionale e restituisce la risposta alla richiesta, restiutisce None in caso di insuccesso
        '''
        try:
            protocol = await aiocoap.Context.create_client_context()
            
            request = aiocoap.Message(code=aiocoap.GET, uri=endpoint)

            logging.info("Richiesta inviata")

            response = await protocol.request(request).response
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
    attuatore= AttuatoreAiocoap()
    logging.info("iter="+str(attuatore.max_iter))
    try:
        if  attuatore.mode=="loop":
            iter=0
            loop=asyncio.get_event_loop()
            while True:
                time.sleep(attuatore.time_unit)
                #Inserire qui i metodi di routine
                loop.run_until_complete(attuatore.state_request())
                #fine metodi di routine
                iter=iter+1
                if iter == attuatore.max_iter:
                    exit("Max iters reached")
        else:
            logging.info("Console mode:")
            logging.info("-1 StateRequest\n-0 Exit")
            while True:
                run_command(attuatore,input(">"))

    except Exception as ex:
        logging.error(ex)
        logging.error("Actuator cannot be instantiated")
        exit()


def run_command(attuatore,cmd):
    loop=asyncio.get_event_loop()
    if cmd == '1':
        loop.run_until_complete(attuatore.state_request())
    elif cmd == '0':
        exit("Bye")
    else:
        logging("Comando non valido, repeat")


if __name__ == "__main__":
    asyncio.run(main())