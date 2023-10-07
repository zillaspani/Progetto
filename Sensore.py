import time
import asyncio
import aiocoap

from colorama import Fore
from aiocoap import *

class Sensore:
    def __init__(self, server_uri,):
        self.server_uri = server_uri
        self.dati = {"umidita": 0.0, "temperatura": 0.0}

    def set_dati(self, umidita, temperatura):
        self.dati["umidita"]=umidita
        self.dati["temperatura"]=temperatura
        
 
    async def send_data(self, umidita, temperatura):
        protocol = await aiocoap.Context.create_client_context()
        payload2 = f"Umidita: {umidita}%, Temperatura: {temperatura} C"

        payload = payload2.encode("utf-8")        
        request = aiocoap.Message(code=aiocoap.POST, uri= self.server_uri, payload=payload)
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
        
'''        
if __name__ == "__main__":
    server_uri = "coap://localhost/data"  # Cambia con l'URI del tuo server CoAP
    sensore = Sensore(server_uri)
    #sensore.set_dati(50,20)
    #umidita = 53.19 #leggerla dalla classe campo
    #temperatura = 27.30 #leggerla dalla classe campo
    while True:
        time.sleep(2)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(sensore.send_data(sensore.dati["umidita"], sensore.dati["temperatura"]))
'''    
