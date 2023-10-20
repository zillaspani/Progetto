import os
import sys
import time
import psutil
import aiocoap
import asyncio
import json

from aiocoap import *
from colorama import Fore
from Sensore import Sensore

class SensoreAiocoap(Sensore):
    
    #Implementazione del metodo astratto presente in Sensore.py
    async def send_dati(self):
        protocol = await aiocoap.Context.create_client_context()
        
        #print(Fore.RED + payload)

        request = aiocoap.Message(code=aiocoap.GET, uri= self.server_uri, payload= json.dumps(self.dati).encode("utf-8"))
        try:
            response = await protocol.request(request).response
            
        except aiocoap.error.RequestTimedOut:
            print(Fore.RED+"Request timed out")
            return
        if response.code.is_successful():
            print(Fore.RED+"Messaggio inviato con successo")
            print()
            
        else:
            print(Fore.RED+f"Errore nella risposta: {response.code}")
        await protocol.shutdown()


server_uri = sys.argv[1] #per prendere il server_uri da terminale

sensore= SensoreAiocoap(server_uri)
#sensore.print_info(os.path.abspath(__file__), psutil.net_if_addrs())
while True:
    time.sleep(5)
    data=sensore.set_dati()
    loop=asyncio.get_event_loop()
    loop.run_until_complete(sensore.send_dati())
