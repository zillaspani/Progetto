import subprocess
import sys
import time

import psutil
LOGGER="../src/sensore/loggerbypid.py"
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

def print_error():
    print("Errore: L'argomento deve essere un numero valido.")
    print("Usage: server.py <int>")
    for i in range(len(file_list)):
        print(f"- {i} for {file_list[i]}")

def get_process_pid(process_name):
    for process in [psutil.Process(pid) for pid in psutil.pids()]:
        if(process.name() == process_name):
            return process.pid


if __name__ == "__main__":
    if len(sys.argv) == 2:
        try:
            number = int(sys.argv[1])
            if 0 <= number < len(file_list):
                command = ["python3", FILE_PATH + file_list[number]+".py"]
                client=subprocess.Popen(command)
                time.sleep(1)
                pid=get_process_pid("sensore0")
                print("Pid: "+str(pid))
                command2 = ["sudo","python3",LOGGER,str(pid),file_list[number]]
                logger=subprocess.Popen(command2)
            else:
                print_error()
        except ValueError:
            print_error()
    else:
        print_error()
