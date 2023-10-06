import time
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
ph_MAX=0.0
ph_MIN=14.0
ph_BASE=7.0

class Campo:
    def _init_(self, umidita, temperatura, ph):
        self.umidita = umidita
        self.temperatura = temperatura
        self.ph = ph
        self.attuatore=False

 

    def stampa_dati(self):
        print(f"Umidità: {self.umidita}%")
        print(f"Temperatura: {self.temperatura}°C")
        print(f"pH: {self.ph}")

 

# Utilizzo della classe
dati = Campo(50, 25, 7)
dati.stampa_dati()

def attuatore_aperto(self, incremento):
        self.umidita += incremento
        self.temperatura -= incremento

 

def attuatore_chiuso(self, decremento):
    self.umidita -= decremento
    self.temperatura += decremento