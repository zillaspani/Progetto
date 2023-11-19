#!/bin/bash

PY_PATH="/usr/bin/python3"
PATH="../src"
SERVER_PY="/server/ServerAiocoap.py"
ATTUATORE_PY="/attuatore/AttuatoreAiocoap.py"
SENSORE_PY="/sensore/SensoreAiocoap.py"
TERMINAL="/usr/bin/x-terminal-emulator"

echo "Avvio del server..."
$TERMINAL -e "$PY_PATH $PATH$SERVER_PY"

echo "Avvio del sensore..."
$TERMINAL -e "$PY_PATH $PATH$SENSORE_PY"

echo "Avvio dell'attuatore..."
$TERMINAL -e "$PY_PATH $PATH$ATTUATORE_PY"
