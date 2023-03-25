#!/bin/bash

#####################################
#########    DEPRECATED   ###########
#####################################

CA_SERVER_IP=85.230.191.21
CA_SERVER_PORT=6666

echo -e "\n\nInput DIR for client's key and generating CSR.\n (The key must names "client-key.pem". If key is not found, it'll be generated.)"
read -p "Current dir used if omitted:" dir_var
if [ ! $dir_var ]
then 
	dir_var="."
fi
mkdir -p $dir_var

if [ -f $dir_var/client-key.pem ]; then
  echo "File Found."
else
  echo "File Not Found. Generating..."
  openssl genrsa -out $dir_var/client-key.pem 4096
fi

# Generate CSR
openssl req -new -key $dir_var/client-key.pem -out $dir_var/client-req.pem -subj "/C=SE/ST=Stockholm/L=Stockholm/O=ACME/OU=Headquarters/CN=$USER.acme.com/emailAddress=info@acme.com"

# send the file to the server
echo "Sending file to server..."
nc -q 1 $CA_SERVER_IP $CA_SERVER_PORT < $dir_var/client-req.pem

# receive the modified file from the server
echo "Receiving modified file from server..."
nc -lv -q 1 $CA_SERVER_PORT > $dir_var/client-cert.pem

# complete and display certificate
echo "Complete!"
openssl x509 -in $dir_var/client-cert.pem -noout -text