import datetime
import logging

import asyncio

import aiocoap.resource as resource
from aiocoap.numbers.contentformat import ContentFormat
import aiocoap
import aiocoap.resource as resource
import aiocoap
import asyncio
class Server(resource.Resource):
    def __init__(self):
        super().__init__()
        self.dati = {"umidita": 0.0, "temperatura": 0.0, "ph": 0.0}
        ''' legggenda
            0 -> lascia cosi com'è, 
            1 -> spegni l'attuatore 
            2 -> accendi l'attuatore
        '''
        self.risposta= 0
        
    async def render_get(self, request): #si riferisce agli attuatori
        #payload2=f"Umidita: {self.dati['umidita']}%, Temperatura: {self.dati['temperatura']}C, ph: {self.dati['ph']}"
        print("Sto ricevendo una get, comunicazione con l'attuatore per decidere sul suo stato")
        if self.dati["umidita"] < 40 or self.dati["temperatura"] > 30:
            self.risposta= 2
        elif self.dati["umidita"] > 60 or self.dati["temperatura"]< 25:
             self.risposta=1 
        else:
            self.risposta=0
        payload2=f"{self.risposta}"
        payload=payload2.encode("utf-8")
        response = aiocoap.Message(payload=payload)
        return response
    
    async def render_post(self, request): #post si riferisce ai sensori 
        print("Sto ricevendo una post, comunicazione con il sensore per ricevere i dati")
        payload = request.payload.decode()
        try:
            split_values = payload.split(',')
            for part in split_values:
                if "Umidita" in part:
                    umidita = float(part.split(':')[-1].strip().rstrip('%'))
                    self.dati["umidita"] = umidita
                elif "Temperatura" in part:
                    temperatura = float(part.split(':')[-1].strip().rstrip('C'))
                    self.dati["temperatura"] = temperatura
                elif "ph" in part:
                    ph = float(part.split(':')[-1].strip())
                    self.dati["ph"] = ph
            print("Umidita: " + str(self.dati["umidita"]) +"%, Temperatura: " + str(self.dati["temperatura"])+ " C, ph: " +str(self.dati["ph"]))
            return aiocoap.Message(code=aiocoap.CHANGED)
        except ValueError:
            print(aiocoap.BAD_REQUEST)
            return aiocoap.Message(code=aiocoap.BAD_REQUEST)
    

            
if __name__ == "__main__":
    root = resource.Site()
    root.add_resource(('data',), Server())
    print("Server OK")
    asyncio.get_event_loop().run_until_complete(aiocoap.Context.create_server_context(root))
    asyncio.get_event_loop().run_forever()
