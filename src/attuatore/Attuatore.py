import json
import logging
import sys

from colorama import Fore
from abc import abstractmethod



class Attuatore:
    def __init__(self, server_uri):
        self.server_uri = "coap://"+server_uri+"/"
        self.stato= False
        logging.basicConfig(level=logging.INFO)
        logging.getLogger("coap-server").setLevel(logging.DEBUG)
    
    
    def get_stato(self):
        return self.stato
    
    def set_stato(self,stato):
        self.stato=stato
    


    #Metodo comune a tutti gli attuatori per stampare informazioni di debug 
    def print_info(self, current_uri, network_interfaces):
        #current_uri = os.path.abspath(__file__)
        print(Fore.GREEN+ "URI dell'attuatore corrente:", current_uri)
        print()
        #network_interfaces = psutil.net_if_addrs()
        interface_name = "eth0"
        ip_address = network_interfaces[interface_name][0].address
        print(f"Indirizzo IP dell'interfaccia {interface_name} dell'attuatore: {ip_address}")
        print()
    
    #Metodo astratto per implementare secondo quali politiche/librerie inviare i dati al server
    @abstractmethod
    def invia_richiesta(self):
        pass

    @abstractmethod
    def send_get_request(self,endpoint,payload):
        pass

    async def state_request(self):
        '''
        Invia una richiesta al server per conoscere in quale stato deve essere l'attuatore
        '''
        endpoint=self.server_uri+"receive"
        response=await self.send_get_request(endpoint,None)
        if response!=None:
            payload=json.loads(response.payload.decode())
            
            print(payload['state'])
        



    #Metodo comune a tutti gli attuatori che analizzano il numero ricevuto dal server
    async def esegui(self): 
        comando = await self.invia_richiesta()
        if comando is not None:
            print(Fore.GREEN+f"Risposta dal server: {comando}")
            if comando == 1 :
                if self.stato:
                    print("L'attuatore è già acceso, è necessario mantenere questo stato")
                else:
                    print(Fore.GREEN+f"Bisogna accendere l'attuatore")
                    self.stato= True
                    print(Fore.GREEN+f"L'attuatore è stato acceso correttamente")
            elif comando == 0:
                if not self.stato: 
                    print("L'attuatore è già spento, è necessario mantenere questo stato")
                else:
                    print(Fore.GREEN+f"Bisogna spengnere l'attuatore")
                    self.stato=False
                    print (Fore.GREEN+ f"L'attuatore è stato spento correttamente")
                
            else:
                if self.stato==False:
                    stato="spento"
                else:
                    stato="acceso"
                print(Fore.GREEN+f"I valori sono buoni, l'attuatore resta {stato}")
            print()
                
        else:
            print(Fore.GREEN+"Impossibile ottenere una risposta dal server")
    


    
    

#Controllo fatto quando si lancia l'attuatore per verificare che sia specificato il server
if len(sys.argv) != 2:
    print("Usage: python3 Attuatore*.py <IP_SERVER> ONLY IP")
    sys.exit(1)
 