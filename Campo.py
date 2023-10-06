import time
from threading import Thread
INCREMENTO=0.1
DECREMENTO=0.1
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

class Campo:

    def __init__(self, umidita, temperatura, ph):
        self.umidita = umidita
        self.temperatura = temperatura
        self.ph = ph
        self.attuatore=False
    def stampa_dati(self):
        print(f"Umidità: {self.umidita}%")
        print(f"Temperatura: {self.temperatura}°C")
        print(f"pH: {self.ph}")


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
                time.sleep=2
                if campo.attuatore:
                    campo.attuatore_aperto(0.05)
                else:
                    campo.attuatore_chiuso(0.03)

class AndamentoStampa (Thread):
        def __init__(self, nome,campo):
            Thread.__init__(self)
            self.nome = nome
            self.campo=campo
        def run(self):
            while True:
                time.sleep=2
                campo.stampa_dati
                 
                 

                 
if __name__ == "__main__":
    campo = Campo(U_BASE,T_BASE,PH_BASE)
    threadAndamento = Andamento("T1",campo)
    threadStampa= AndamentoStampa("T2",campo)
    print("ciao")
    threadAndamento.start()
    threadStampa.start()


#thread1 = Lancio("prova 1")
#thread1.start()    
