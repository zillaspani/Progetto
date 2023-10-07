import time
from Sensore import *
from Attuatore import *
from threading import Thread
from colorama import Fore
INCREMENTO_U=1.5
DECREMENTO_U=1
#Soglie temperatura
T_MAX=40.0
T_MIN=-20.0
T_BASE=20.0
#Soglie umidità
U_MAX=100.0
U_MIN=0.0
U_BASE=50.0
#Soglie acidità
PH_MAX=0.0
PH_MIN=14.0
PH_BASE=7.0
#EndPoint Server:
EPDATA="coap://localhost/data"

class Campo:

    def __init__(self, umidita, temperatura, ph):
        self.umidita = umidita
        self.temperatura = temperatura
        self.ph = ph
        self.attuatore=False
    


    def stampa_dati(self):
        print(Fore.CYAN+f"Umidità: {self.umidita}%")
        print(f"Temperatura: {self.temperatura}°C")
        print(f"pH: {self.ph}")

    def get_Temperatura(self):
         return self.temperatura
    
    def get_umidita(self):
         return self.umidita
    

    def attuatore_aperto(self, incremento):
            self.umidita += incremento
            #self.temperatura -= incremento

 
    def attuatore_chiuso(self, decremento):
        self.umidita -= decremento
        #self.temperatura += decremento

class Andamento (Thread):
        def __init__(self, nome,campo):
            Thread.__init__(self)
            self.nome = nome
            self.campo=campo
        def run(self):
            while True:
                time.sleep(2)
                if campo.attuatore:
                    campo.attuatore_aperto(INCREMENTO_U)
                else:
                    campo.attuatore_chiuso(DECREMENTO_U)

class AndamentoStampa (Thread):
        def __init__(self, nome,campo):
            Thread.__init__(self)
            self.nome = nome
            self.campo=campo
        def run(self):
            while True:
                time.sleep(2)
                campo.stampa_dati()
                 
                 

                 
if __name__ == "__main__":
    campo = Campo(U_BASE,T_BASE,PH_BASE)
    threadAndamento = Andamento("T1",campo)
    threadStampa= AndamentoStampa("T2",campo)
    threadAndamento.start()
    threadStampa.start()
    s = Sensore(EPDATA)
    a = Attuatore(EPDATA)


    while True:
        time.sleep(2)
        loop = asyncio.get_event_loop()
        s.set_dati(campo.get_umidita(),campo.get_Temperatura())
        loop.run_until_complete(s.send_data(s.dati["umidita"], s.dati["temperatura"]))
        #loop = asyncio.get_event_loop()
        loop.run_until_complete(a.esegui())
        campo.attuatore=a.get_stato()




