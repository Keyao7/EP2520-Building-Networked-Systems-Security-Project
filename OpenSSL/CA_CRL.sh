#!/bin/bash

# openssl ca -gencrl -keyfile ca.key -cert ca.pem -config ca.cnf -out ca-crl.pem
openssl ca -gencrl -keyfile ca.key -cert ca.pem -config ca.cnf -out ca-crl.pem
openssl crl -in ca-crl.pem -outform der -out ca.crl
# rm ca-crl.pem