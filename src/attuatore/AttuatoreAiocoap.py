import os
import sys
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


server_uri = sys.argv[1] #per prendere il server_uri da terminale

attuatore= AttuatoreAiocoap(server_uri)
attuatore.print_info(os.path.abspath(__file__), psutil.net_if_addrs())
'''while True:
    time.sleep(5)
    loop=asyncio.get_event_loop()
    loop.run_until_complete(attuatore.state_request())
'''
loop=asyncio.get_event_loop()
loop.run_until_complete(attuatore.state_request())


