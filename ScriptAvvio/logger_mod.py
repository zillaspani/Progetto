import subprocess
import sys
import psutil
import time
import os

import setproctitle
#import progressbar
FILE_PATH = "../src/sensore/"

file_list = [
    "SensoreAiocoap",
    "SensoreCoapthon_dtls_ec",
    "SensoreCoapthon_dtls",
    "SensoreDTLS",
    "SensoreSecureChallenge_Response_128_256",
    "SensoreSecureChallenge_Response_256_384",
    "SensoreSecureDH_RSA_128_256",
    "SensoreSecureDH_RSA_256_384",
    "SensoreSecureECDHE_ECDSA_128_256",
    "SensoreSecureECDHE_ECDSA_256_384",
    "SensoreSecureECDHE_RSA_128_256",
    "SensoreSecureECDHE_RSA_256_384",
]
interval=5
number_of_cpu=30
interface="lo"#eth0
mwh_cost=0.2777778

def get_process_pid(process_name):
    for process in [psutil.Process(pid) for pid in psutil.pids()]:
        if(process.name() == process_name):
            return process.pid

def analyze_ram_and_cpu_of_a_process(process_name,test_name, maximum = number_of_cpu):
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
        print("#########")
        print(process.connections)
        print("#########")
        conn=process.connections()[0].laddr
        
        try:
            command = ["sudo","tcpdump","-ni", interface, "-s0", "-w", process_name+".pcap","host",conn[0], "and","udp", "port",str(conn[1]) ]
            tcpdump_process = subprocess.Popen(command)
            
            time_s=time.time()
            i = 0
            total_mwh=0
            while(i<maximum):
                time_start=time.time()
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
        except KeyboardInterrupt as ki:
            CSV.close()
            print('Fine')

def print_error():
    print("Errore: L'argomento deve essere un numero valido.")
    print("Usage: server.py <int>")
    for i in range(len(file_list)):
        print(f"- {i} for {file_list[i]}")            

def main():
    if len(sys.argv) == 2:
        try:
            number = int(sys.argv[1])
            if 0 <= number < len(file_list):
                command = ["python3", FILE_PATH + file_list[number]+".py"]
                client=subprocess.Popen(command)
                setproctitle.setproctitle("sensore0")
                time.sleep(5)
                analyze_ram_and_cpu_of_a_process("sensore0",file_list[number], maximum = number_of_cpu)
            else:
                print_error()
        except ValueError:
            print_error()
    else:
        print_error()
    




main()
