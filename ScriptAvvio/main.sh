#!/bin/bash

PY_PATH="/usr/bin/python3"
PATH="../src"
SERVER_PY="/server/Server"
ATTUATORE_PY="/attuatore/Attuatore"
SENSORE_PY="/sensore/Sensore"
TERMINAL="/usr/bin/x-terminal-emulator"
CAT="/bin/cat"
VERSION=""

$CAT easter_egg.txt

while true; do
    echo "Inserisci un numero per selezionare una versione del software"
    echo "(o 'exit' per uscire): "
    echo " 1 - NoSec"
    echo " 2 - OurSec"
    echo " 3 - dTLS with Aiocoap"
    echo " 4 - dTLS with Coapthon"
    read -p ">" input

    if [ "$input" == "exit" ]; then
        echo "Chiusura..."
        exit
    fi

    if [[ "$input" =~ ^[0-9]+$ ]]; then
        case $input in
            1)
                echo "Hai selezionato la versione NoSec"
                VERSION="Aiocoap.py"
                ;;
            2)
                echo "Hai selezionato la versione OurSec"
                VERSION="Secure.py"
                ;;
            3)
                echo "Hai selezionato la versione dTLS with Aiocoap"
                VERSION="DTLS.py"
                ;;
            4)
                echo "Hai selezionato la versione dTLS"
                VERSION="DTLSCoapthon.py"
                ;;
            *)
                echo "Selezione non valida. Inserisci un numero valido."
                ;;
        esac
    else
        echo "Input non valido. Per favore, inserisci un numero valido."
    fi

    if [ "$VERSION" != "" ]; then
        while true; do
            echo "Inserisci un numero per selezionare il tipo di dispositivo"
            echo "(o 'b' per tornare indietro): "
            echo " 1 - Server"
            echo " 2 - Sensore"
            echo " 3 - Attuatore"
            read -p ">" input_device

            if [ "$input_device" == "b" ]; then
                echo "Torno indietro."
                break
            fi

            if [[ "$input_device" =~ ^[0-9]+$ ]]; then
                case $input_device in
                    1)
                        echo "Hai selezionato Server"
                        $TERMINAL -e "$PY_PATH $PATH$SERVER_PY$VERSION"
                        ;;
                    2)
                        echo "Hai selezionato Sensore"
                        $TERMINAL -e "$PY_PATH $PATH$SENSORE_PY$VERSION"
                        ;;
                    3)
                        echo "Hai selezionato Attuatore"
                        $TERMINAL -e "$PY_PATH $PATH$ATTUATORE_PY$VERSION"
                        ;;
                    *)
                        echo "Selezione non valida. Inserisci un numero valido."
                        ;;
                esac
            else
                echo "Input non valido. Per favore, inserisci un numero valido."
            fi
        done
    fi
done
