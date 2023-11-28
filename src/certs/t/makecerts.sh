#!/bin/bash -eu
DIR=`dirname "$0"`
openssl genpkey -genparam -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out dh.param
# Genera un certificato per la CA
openssl req -config "$DIR/openssl_ca.cnf" -new -x509 -newkey ec:dh.param -nodes -keyout ca.key -out ca-cert.pem -days 3650

# Genera una richiesta di certificato per il server
openssl req -config "$DIR/openssl_ca.cnf" -new -newkey ec:dh.param -nodes -keyout server.key -out server.pem

# Firma la richiesta di certificato con la CA
openssl x509 -req -in server.pem -CA ca-cert.pem -CAkey ca.key -CAcreateserial -days 3650 -out server.pem

# Combina la chiave privata del server e il certificato firmato in un file PEM
cat server.key server.pem > keycert.pem

# Rimuovi i file temporanei
rm server.csr

# Stampa il messaggio di completamento
echo "I certificati sono stati generati con successo."