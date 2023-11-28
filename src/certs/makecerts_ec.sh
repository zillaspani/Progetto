# Generate self-signed certificate for the certificate authority
echo Generating CA...
openssl ecparam -name prime256v1 -genkey -out tmp_ca_ec.key
openssl req -config "openssl_ca.cnf" -x509 -new -SHA384 -nodes -keyout tmp_ca_ec.key -days 3650 -out ca-cert_ec.pem
# Generate a certificate request
echo Generating certificate request...
openssl ecparam -name prime256v1 -genkey -out tmp_server_ec.key
openssl req -config "openssl_server.cnf" -new -SHA384 -nodes -keyout tmp_server_ec.key -out tmp_server_ec.req
# Sign the request with the certificate authority's certificate created above
echo Signing certificate request...
openssl req -in tmp_server_ec.req -noout
openssl x509 -req -SHA384 -days 3650 -in tmp_server_ec.req -CA ca-cert_ec.pem -CAkey tmp_ca_ec.key -CAcreateserial -out server-cert_ec.pem
# Build pem file with private and public keys, ready for unprompted server use
cat tmp_server_ec.key server-cert_ec.pem > keycert_ec.pem
# Clean up
rm tmp_ca_ec.key tmp_server_ec.key tmp_server_ec.req ca-cert_ec.srl
