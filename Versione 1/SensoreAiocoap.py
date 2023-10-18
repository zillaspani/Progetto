from aiocoap import *
from colorama import Fore
from Sensore import Sensore

import sys
import time
import aiocoap
import asyncio

class SensoreAiocoap(Sensore):
    
    async def send_dati(self):
        protocol = await aiocoap.Context.create_client_context()
        payload = f"Umidita: {self.dati['umidita']}%, Temperatura: {self.dati['temperatura']} C"
        print(Fore.RED + payload)

        request = aiocoap.Message(code=aiocoap.POST, uri= self.server_uri, payload=payload.encode("utf-8"))
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

server_uri = sys.argv[1]
sensore= SensoreAiocoap(server_uri)
sensore.print_info()
while True:
    time.sleep(5)
    data=sensore.set_dati()
    loop=asyncio.get_event_loop()
    loop.run_until_complete(sensore.send_dati())
