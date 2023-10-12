import logging
import asyncio
import aiocoap

from aiocoap import *

class Sensore:
    def __init__(self, server_uri):
        self.server_uri = server_uri

 
    async def send_data(self, umidita, temperatura, ph):
        protocol = await aiocoap.Context.create_client_context()
        payload2 = f"Umidita: {umidita}%, Temperatura: {temperatura} C, ph: {ph}"

        payload = payload2.encode("utf-8")        
        request = aiocoap.Message(code=aiocoap.POST, uri= server_uri, payload=payload)
        try:
            response = await protocol.request(request).response
            
        except aiocoap.error.RequestTimedOut:
            print("Request timed out")
            return
        if response.code.is_successful():
            print("Messaggio inviato con successo")
            print(response.code)
        else:
            print(f"Errore nella risposta: {response.code}")
        await protocol.shutdown()
if __name__ == "__main__":
    server_uri = "coap://localhost/data"  # Cambia con l'URI del tuo server CoAP
    client = Sensore(server_uri)
   
    umidita = 53.19 #leggerla dalla classe campo
    temperatura = 27.30 #leggerla dalla classe campo
    ph = 7.0 #leggerla dalla classe campo
    
    loop = asyncio.get_event_loop()
    loop.run_until_complete(client.send_data(umidita, temperatura, ph))