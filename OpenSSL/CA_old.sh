#!/bin/bash

CA_USER="pi"
CA_SERVER="85.230.191.21"
CA_DIR="~/CA"

echo -e "\n\nInput path for generating client CSR."
read -p "Current dir used if omitted:" dir_var
if [ ! $dir_var ]
then 
	dir_var="."
fi
mkdir -p $dir_var

echo -e "\n\nNow Generating key and CSR"

openssl req -newkey rsa:4096 -nodes -keyout $dir_var/client-key.pem -out $dir_var/client-req.pem -subj "/C=SE/ST=Stockholm/L=Stockholm/O=ACME/OU=Headquarters/CN=$USER.acme.com/emailAddress=info@acme.com"

echo -e "\n\nClient CSR is under \"${dir_var}\". Sending to CA..."

scp $dir_var/client-req.pem "${CA_USER}@${CA_SERVER}:${CA_DIR}/client/client-req.pem"

ssh $CA_USER@$CA_SERVER <<'ENDSSH'

#commands to run on remote host

openssl x509 -req -in ./CA/client/client-req.pem -days 60 -CA ./CA/ca-cert.pem -CAkey ./CA/ca-key.pem -CAcreateserial -out ./CA/client/client-cert.pem

ENDSSH

scp "${CA_USER}@${CA_SERVER}:${CA_DIR}/client/client-cert.pem"  ./

echo -e "\n\nclient-cert.pem is under local dir.\nComplete. "
