#!/bin/bash

files=$(ls *.pem 2> /dev/null | wc -l)
if [ "$files" != "0" ]; then
	rm *.pem
fi
files=$(ls *.csr 2> /dev/null | wc -l)
if [ "$files" != "0" ]; then
	rm *.csr
fi

read -p "Press enter to continue: Check OpenSSL verion (locally)"
# Check OpenSSL verion (locally)
openssl version

read -p "Press enter to continue: 1. Generate ROOT's private key and self-signed.pemtificate"
# 1. Generate ROOT's private key and self-signed.pemtificate
if [ ! -f root.key ]; then
	openssl genrsa -out root.key 4096
fi

if [ -f root.cnf ]; then
	openssl req -x509 -key root.key -days 365 -nodes -out root.pem -config root.cnf
else
	openssl req -x509 -key root.key -days 365 -nodes -out root.pem -subj "/C=SE/ST=Stockholm/L=Stockholm/O=KTH/OU=NSS-BNSS/CN=root.demo.com/emailAddress=root@demo.com"
fi

# 2. Generate CA server's private key and.pemtificate signing request (CSR)
read -p "Press enter to continue: 2. Generate CA server's private key and certificate signing request (CSR)"
if [ ! -f ca.key ]; then
	openssl genrsa -out ca.key 4096
fi
if [ -f ca.cnf ]; then
	openssl req -new -key ca.key -nodes -out ca.csr -config ca.cnf
else
	openssl req -new -key ca.key -nodes -out ca.csr -subj "/C=SE/ST=Stockholm/L=Stockholm/O=ACME/OU=Headquarters/CN=ca.demo.com/emailAddress=info@demo.com"
fi

# 3. Use ROOT's private key to sign CA server's CSR and get back the signed certificate
read -p "Press enter to continue: 3. Use ROOT's private key to sign CA server's CSR and get back the signed certificate"
openssl x509 -req -in ca.csr -days 60 -CA root.pem -CAkey root.key -CAcreateserial -out ca.pem

# 4. Form certificate chain
echo "Certificate chain has been generated."
cat root.pem ca.pem > cert-bundle.pem
