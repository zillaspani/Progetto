from abc import abstractmethod
from colorama import Fore

import os 
import sys
import psutil
import socket
import random

class Sensore:    
    def __init__(self, server_uri):
        self.server_uri = server_uri
        self.dati = {"umidita": 0.0, "temperatura": 0.0}

    #Metodo comune a tutti i sensore per generare i valori randomici di umidita e temperatura
    def set_dati(self):
        umidita=random.uniform(40.0,60.0)
        temperatura=random.uniform(15.0,25.0)
        self.dati["umidita"]=round(umidita, 2)
        self.dati["temperatura"]=round(temperatura,2)
    
    
    #Metodo comune a tutti i sensori per stampare informazioni di debug 
    def print_info(self):
        current_uri = os.path.abspath(__file__)
        print(Fore.RED+ "URI del file sensore corrente:", current_uri)
        print()
        network_interfaces = psutil.net_if_addrs()
        interface_name = "eth0"
        ip_address = network_interfaces[interface_name][0].address
        print(f"Indirizzo IP dell'interfaccia {interface_name}: {ip_address}")
        print()
        
    
    #Metodo astratto per implementare secondo quali politiche/librerie inviare i dati al server
    @abstractmethod
    def send_dati(self):
        pass


#Controllo fatto quando si lancia il sensore per verificare che sia specificato il server
if len(sys.argv) != 2:
    print("Usage: python3 Sensore*.py <server_uri>")
    sys.exit(1)
 
