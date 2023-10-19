import os
import sys
import time
import psutil
import asyncio
import aiocoap

from aiocoap import *
from colorama import Fore
from Attuatore import Attuatore


class AttuatoreAiocoap(Attuatore):
    
    async def invia_richiesta(self):
        protocol = await aiocoap.Context.create_client_context()
        request = aiocoap.Message(code=aiocoap.GET, uri=self.server_uri)
        try:
            response = await protocol.request(request).response
        except aiocoap.error.RequestTimedOut:
            print(Fore.GREEN+"Richiesta al server CoAP scaduta")
            return None
        if response.code.is_successful():
            try:
                numero_intero = int(response.payload)
                return numero_intero
            except ValueError:
                print(Fore.GREEN+"Il server ha inviato una risposta non valida")
                return None
        else:
            print(Fore.GREEN+f"Errore nella risposta del server: {response.code}")
            return None
    
    


server_uri = sys.argv[1] #per prendere il server_uri da terminale

attuatore= AttuatoreAiocoap(server_uri)
attuatore.print_info(os.path.abspath(__file__), psutil.net_if_addrs())
while True:
    time.sleep(5)
    loop=asyncio.get_event_loop()
    loop.run_until_complete(attuatore.esegui())


