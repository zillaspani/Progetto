import logging
import asyncio
import aiocoap

from aiocoap import *
class Attuatore:
    def __init__(self, server_uri):
        self.server_uri = server_uri

    async def invia_richiesta(self):
        protocol = await aiocoap.Context.create_client_context()
        request = aiocoap.Message(code=aiocoap.GET, uri=self.server_uri)
        try:
            response = await protocol.request(request).response
        except aiocoap.error.RequestTimedOut:
            print("Richiesta al server CoAP scaduta")
            return None
        if response.code.is_successful():
            try:
                numero_intero = int(response.payload)
                return numero_intero
            except ValueError:
                print("Il server ha inviato una risposta non valida")
                return None
        else:
            print(f"Errore nella risposta del server: {response.code}")
            return None
    async def esegui(self, ):
        comando = await self.invia_richiesta()
        if comando is not None:
            print(f"Risposta dal server: {comando}")
            if comando == 2 :
                print(f"Bisogna accendere l'attuatore")
                '''questo comporterà la chiamata di un metodo nella classe campo che si occuperà di 
                    decrementare la temperatura e incrementare l'umidità nel tempo'''
            
            elif comando == 1: 
                print(f"Bisogna spengnere l'attuatore")
                '''questo comporterà la chiamata di un metodo nella classe campo che si occuperà di 
                    incrementare la temperatura e decrementare l'umidità nel tempo'''
            else:
                print(f"I valori sono buoni, lascia l'attuatore nel suo stato attuale") 
                #doNothing nella classe campo
            


        else:
            print("Impossibile ottenere una risposta dal server")
if __name__ == "__main__":
    server_uri = "coap://localhost/data"  # Cambia con l'URI del tuo server CoAP
    client = Attuatore(server_uri)
    
    loop = asyncio.get_event_loop()
    loop.run_until_complete(client.esegui())