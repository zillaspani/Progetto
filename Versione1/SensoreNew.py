import time
import asyncio
import aiocoap

from colorama import Fore
from aiocoap import *

class Sensore:
    def __init__(self, server_uri,):
        self.server_uri = server_uri

         
    async def send_data(self, umidita, temperatura):
        protocol = await aiocoap.Context.create_client_context()
        payload = f"Umidita: {umidita}%, Temperatura: {temperatura} C"  
        request = aiocoap.Message(code=aiocoap.POST, uri= self.server_uri, payload=payload.encode("utf-8") )
        try:
            response = await protocol.request(request).response
            
        except aiocoap.error.RequestTimedOut:
            print(Fore.RED+"Request timed out")
            return
        if response.code.is_successful():
            print(Fore.RED+"Messaggio inviato con successo")
            print(response.code)
        else:
            print(Fore.RED+f"Errore nella risposta: {response.code}")
        await protocol.shutdown()
        
        
if __name__ == "__main__":
    server_uri = "coap://localhost/data"  # Cambia con l'URI del tuo server CoAP
    sensore = Sensore(server_uri)
    umidita = 53.19 #leggerla dalla classe campo
    temperatura = 27.30 #leggerla dalla classe campo
    while True:
        time.sleep(2)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(sensore.send_data(umidita, temperatura))
