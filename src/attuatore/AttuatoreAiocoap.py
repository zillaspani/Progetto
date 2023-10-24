import os
import sys
import time
import psutil
import asyncio
import aiocoap
import logging
from aiocoap import *
from colorama import Fore
from Attuatore import Attuatore


class AttuatoreAiocoap(Attuatore):
        
    async def send_get_request(self, endpoint,payload):
        '''
        Metodo che invia ad un endpoint una get con payload opzionale e restituisce la risposta alla richiesta, restiutisce None in caso di insuccesso
        '''
        #return super().send_get_request(endpoint)
        try:
            protocol = await aiocoap.Context.create_client_context()
            if payload==None:
                request = aiocoap.Message(code=aiocoap.GET, uri=endpoint)
            else:
                request = aiocoap.Message(code=aiocoap.GET, uri=endpoint,payload=payload)

            response = await protocol.request(request).response
            logging.info(Fore.GREEN+"Richiesta inviata")
        except aiocoap.error.RequestTimedOut:
            logging.info(Fore.GREEN+"Richiesta al server CoAP scaduta")
            return None
        if response.code.is_successful():
            try:
                return response
            except ValueError:
                logging.info(Fore.GREEN+"Il server ha inviato una risposta non valida")
                return None
        else:
            logging.info(Fore.GREEN+f"Errore nella risposta del server: {response.code}")
            return None

'''
attuatore= AttuatoreAiocoap()
attuatore.print_info(os.path.abspath(__file__), psutil.net_if_addrs())
while True:
    time.sleep(5)
    loop=asyncio.get_event_loop()
    loop.run_until_complete(attuatore.state_request())

loop=asyncio.get_event_loop()
loop.run_until_complete(attuatore.state_request())
'''


def main():
    attuatore= AttuatoreAiocoap()
    attuatore.print_info(os.path.abspath(__file__), psutil.net_if_addrs())
    print(attuatore.max_iter)
    print(attuatore.mode)   
    try:
        if  attuatore.mode=="loop":
            iter=0
            loop=asyncio.get_event_loop()
            while True:
                time.sleep(attuatore.time_unit)
                #Inserire qui i metodi di routine
                loop.run_until_complete(attuatore.state_request())
                #time.sleep(attuatore.time_interval)
                #loop.run_until_complete(attuatore.health_request())

                #fine metodi di routine
                iter=iter+1
                if iter == attuatore.max_iter:
                    exit("Max iters reached")
        else:
            print("Console mode:")
            print("-1 StateRequest\n-2 HealthRequest\n-0 Exit")
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
    elif cmd == '2':
        loop.run_until_complete(attuatore.health_request())
    elif cmd == '0':
        exit("Bye")
    else:
        print("Comando non valido, repeat")


if __name__ == "__main__":
    asyncio.run(main())