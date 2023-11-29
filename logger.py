import subprocess
import sys
import psutil
import time
import os
from scapy.utils import wrpcap
from scapy.all import sniff

interval=5
number_of_packets=1
number_of_cpu=1
interface="lo"

def get_process_pid(process_name):
    for process in [psutil.Process(pid) for pid in psutil.pids()]:
        if(process.name() == process_name):
            return process.pid

print(get_process_pid('sensore0'))

def analyze_ram_and_cpu_of_a_process(process_name, maximum = number_of_cpu):
    try:
        os.remove(process_name+".csv",)
    except:
        pass
    try:
        #os.remove(process_name+".pcap",)
        pass
    except:
        pass

        
    with open(process_name+".csv", "x") as CSV:
        CSV.write("TIME,CPU,RAM, \n")
        process_pid = get_process_pid(process_name)
        process = psutil.Process(process_pid)
        print(process.connections()[0].laddr)
        print(process.name())
        process.cpu_percent()
        test_data = []
        conn=process.connections()[0].laddr
        conn1=process.connections()[0].raddr
               
        try:
            command = ["tcpdump","-v", "-ni", interface, "-s0", "-w", process_name+".pcap","host",conn[0], "and","udp", "port",str(conn[1]),"or","host",conn1[0], "and","udp", "port",str(conn1[1]) ]
            tcpdump_process = subprocess.Popen(command)
            time_s=time.time()
            i = 0
            while(i<maximum):
               
                process_cpu = process.cpu_percent(interval)
                process_ram = process.memory_percent()
                print("CPU%:", process_cpu)
                print("MEM%:", process_ram)
                act=time.time()-time_s
                CSV.write(str(round(act,2))+","+str(process_cpu)+","+str(round(process_ram,2))+",\n")
                i+=1
                test_data.append(process_cpu)
            print(sum(test_data)/len(test_data))
                  
            
            
            # Attende la durata specificata
            time.sleep(2)

            # Termina tcpdump
            tcpdump_process.terminate()
                     
        except KeyboardInterrupt as ki:
            CSV.close()
            print('Fine')
            

def main():
    if len(sys.argv) != 2:
        analyze_ram_and_cpu_of_a_process('sensore0', maximum = number_of_cpu)
    else:
        analyze_ram_and_cpu_of_a_process(sys.argv[1], maximum = number_of_cpu)
main()
'''
Se interval è impostato su None:
In questo caso, la funzione calcola la percentuale di utilizzo della CPU in un unico momento, fornendo il
 valore corrente dell'utilizzo della CPU. In altre parole, restituirà l'utilizzo della CPU in quel preciso istante in cui viene invocata la funzione.

Se interval è un valore numerico:
Quando si specifica un valore numerico per interval (ad esempio 1, 5, o 10), la funzione calcola la percentuale di utilizzo 
della CPU come media degli ultimi campionamenti effettuati durante l'intervallo di tempo specificato. Questo significa che la funzione
 prenderà una serie di campioni durante l'intervallo specificato e calcolerà la media di tali campioni per restituire l'utilizzo della CPU in quel dato momento.
 
 cpu_usage = psutil.cpu_percent(interval=5)
print(cpu_usage)  # Restituirà la media dell'utilizzo della CPU negli ultimi 5 secondi
'''