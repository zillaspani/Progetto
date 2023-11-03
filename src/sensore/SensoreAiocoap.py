import os
import time
import psutil
import aiocoap
import asyncio
import json
import logging
from aiocoap import *
from colorama import Fore
from Sensore import Sensore

class SensoreAiocoap(Sensore):

    async def send_get_request(self, endpoint,payload):
        '''
        Metodo che invia ad un endpoint una get con payload opzionale e restituisce la risposta alla richiesta, restiutisce None in caso di insuccesso
        '''
        try:
            protocol = await aiocoap.Context.create_client_context()
            if payload==None:
                request = aiocoap.Message(code=aiocoap.GET, uri=endpoint)
            else:
                request = aiocoap.Message(code=aiocoap.GET, uri=endpoint,payload=payload)
            logging.info(Fore.GREEN+"Richiesta inviata")

            response = await protocol.request(request).response
            print(response)
        except aiocoap.error.RequestTimedOut:
            logging.info(Fore.GREEN+"Richiesta al server CoAP scaduta")
            return None
        if response.code.is_successful():
            try:
                logging.info(Fore.GREEN+"Il server ha inviato una risposta valida")
                return response
            except ValueError:
                logging.info(Fore.GREEN+"Il server ha inviato una risposta non valida")
                return None
        else:
            logging.info(Fore.GREEN+f"Errore nella risposta del server: {response.code}")
            return None
    
    async def data_request(self):
        data=self.get_field_value()
        endpoint=self.server_uri+"data"
        payload=json.dumps(data).encode("utf-8")
        response=await self.send_get_request(endpoint,payload=payload)
        if response==None:
            logging.error("Something went wrong during server request handling")
    
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
       

def main():
    sensore= SensoreAiocoap()
    #sensore.print_info(os.path.abspath(__file__), psutil.net_if_addrs())
    print(sensore.max_iter)
    print(sensore.mode)   
    try:
        if  sensore.mode=="loop":
            iter=0
            loop=asyncio.get_event_loop()
            while True:
                time.sleep(sensore.time_unit)
                #Inserire qui i metodi di routine
                loop.run_until_complete(sensore.data_request())
                time.sleep(sensore.time_interval)
                loop.run_until_complete(sensore.health_request())

                #fine metodi di routine
                iter=iter+1
                if iter == sensore.max_iter:
                    exit("Max iters reached")
        else:
            print("Console mode:")
            print("-1 DataRequest\n-2 AL MOMENTO NIENTE\n-0 Exit")
            while True:
                run_command(sensore,input(">"))

    except Exception as ex:
        logging.error(ex)
        logging.error("Actuator cannot be instantiated")
        exit()


def run_command(sensore,cmd):
    loop=asyncio.get_event_loop()
    if cmd == '1':
        loop.run_until_complete(sensore.data_request())
    elif cmd == '2':
        loop.run_until_complete(sensore.health_request())
    elif cmd == '0':
        exit("Bye")
    else:
        print("Comando non valido, repeat")


if __name__ == "__main__":
    asyncio.run(main())