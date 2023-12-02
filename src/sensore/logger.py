import subprocess
import sys
import psutil
import time
import os
import progressbar

interval=5
number_of_cpu=30
interface="lo"#eth0
mwh_cost=0.2777778

def get_process_pid(process_name):
    for process in [psutil.Process(pid) for pid in psutil.pids()]:
        if(process.name() == process_name):
            return process.pid

def analyze_ram_and_cpu_of_a_process(process_name,test_name, maximum = number_of_cpu):
    print(process_name)
    print(test_name)
    bar = progressbar.ProgressBar(maxval=number_of_cpu,widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
    try:
        os.remove(test_name+".csv",)
    except:
        pass
    try:
        #os.remove(process_name+".pcap",)
        pass
    except:
        pass

        
    with open(test_name+".csv", "x") as CSV:
        CSV.write("TIME,CPU,RAM,CPU_W,WIFI_UP_W,WIFI_DOWN_W,TOT_W,MWH \n")
        process_pid = get_process_pid(process_name)
        process = psutil.Process(process_pid)
        print("Start logging on "+process_name)
        process.cpu_percent()
        print(process.connections)
        time.sleep(10)
        conn=process.connections()[0].laddr
        
               
        try:
            command = ["sudo","tcpdump","-ni", interface, "-s0", "-w", test_name+".pcap","host",conn[0], "and","udp", "port",str(conn[1]) ]
            tcpdump_process = subprocess.Popen(command)
            
            time_s=time.time()
            i = 0
            total_mwh=0
            bar.start()
            while(i<maximum):
                time_start=time.time()
                bar.update(i)
                packets_counter_old=psutil.net_io_counters(pernic=True)[interface]
                process_cpu = process.cpu_percent(interval)
                process_ram = process.memory_percent()
                packets_counter=psutil.net_io_counters(pernic=True)[interface]
                delta=time.time()-time_start
                process_cpu_energy=1.5778+0.181*process_cpu
                packets_total_up=packets_counter[0]-packets_counter_old[0]
                packets_total_down=packets_counter[1]-packets_counter_old[1]
                packet_rate_up=packets_total_up/delta*pow(10,-6)
                packet_rate_down=packets_total_down/delta*pow(10,-6)
                process_network_energy_up=0.064+4.813*pow(10,-3)*packet_rate_up
                process_network_energy_down=0.057+4.813*pow(10,-3)*packet_rate_down
                total_w=process_cpu_energy+process_network_energy_up+process_network_energy_down+0.942
                total_mwh+=total_w*delta*mwh_cost
                CSV.write(str(round(time.time()-time_s,2))+","+str(process_cpu)+","+str(round(process_ram,2))+","+str(round(process_cpu_energy,2))+","+str(round(process_network_energy_up,2))+","+str(round(process_network_energy_down,2))+","+str(round(total_w,2))+","+str(round(total_mwh,2))+"\n")
                i+=1    
            # Termina tcpdump
            tcpdump_process.terminate()
            bar.finish()         
        except KeyboardInterrupt as ki:
            CSV.close()
            print('Fine')
            

def main():
    '''
    if len(sys.argv) != 2:
        analyze_ram_and_cpu_of_a_process('sensore0',"nope", maximum = number_of_cpu)
    elif len(sys.argv)==3:
        analyze_ram_and_cpu_of_a_process(sys.argv[1],sys.argv[2], maximum = number_of_cpu)
    '''
    analyze_ram_and_cpu_of_a_process(sys.argv[1],sys.argv[2], maximum = number_of_cpu)    
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