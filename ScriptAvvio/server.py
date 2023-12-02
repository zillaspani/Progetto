import subprocess
import sys

FILE_PATH = "../src/server/"

file_list = [
    "ServerAiocoap.py",
    "ServerCoapthon_dtls_ec.py",
    "ServerCoapthon_dtls.py",
    "ServerDTLS.py",
    "ServerSecureChallenge_Response_128_256.py",
    "ServerSecureChallenge_Response_256_384.py",
    "ServerSecureDH_RSA_128_256.py",
    "ServerSecureDH_RSA_256_384.py",
    "ServerSecureECDHE_ECDSA_128_256.py",
    "ServerSecureECDHE_ECDSA_256_384.py",
    "ServerSecureECDHE_RSA_128_256.py",
    "ServerSecureECDHE_RSA_256_384.py",
]

def print_error():
    print("Errore: L'argomento deve essere un numero valido.")
    print("Usage: server.py <int>")
    for i in range(len(file_list)):
        print(f"- {i} for {file_list[i]}")

if __name__ == "__main__":
    if len(sys.argv) == 2:
        try:
            number = int(sys.argv[1])
            if 0 <= number < len(file_list):
                command = ["python3", FILE_PATH + file_list[number]]
                subprocess.Popen(command)
            else:
                print_error()
        except ValueError:
            print_error()
    else:
        print_error()

