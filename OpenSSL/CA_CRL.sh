#!/bin/bash

read -p "Enter certificate to revoke (e.g. client.pem):" revoke_cert
if [ ! $revoke_cert ]; then
   echo "Use default [client.pem]"
   revoke_cert="client.pem"
fi
if [ ! -f $revoke_cert ]; then
    echo "ERR:file not found! Failed."
fi
openssl ca -config ca.cnf -revoke $revoke_cert

read -p "Press enter to continue: CRL generation"
if [ ! -f crlnumber ]; then
    echo 00 > crlnumber
fi
openssl ca -gencrl -keyfile ca.key -cert ca.pem -config ca.cnf -out ca.crl

read -p "Press enter to continue: CRL view"
openssl crl -in ca.crl -text -noout
