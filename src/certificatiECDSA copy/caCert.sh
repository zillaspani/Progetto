DIR=`dirname "$0"`
openssl ecparam -name secp256r1 -genkey -noout -out p256.key
openssl ec -in p256.key -pubout -out p256.pub
openssl req -config "$DIR/openssl_ca.cnf" -new -x509 -days 3652 -key p256.key -out ca-cert.crt