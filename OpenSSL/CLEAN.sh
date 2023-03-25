#!/bin/bash

read -p "Press Enter to clean up all files generated."
rm -fv *.pem *.key *.crl *.csr *.p12 index.txt *.old *.attr serial crlnumber
rm -rfv certs
echo "Complete!"

######################################################
#  #  ca.cnf backup
######################################################

#  # This is default configuration file for OpenSSL
#  # https://www.openssl.org/docs/man1.1.1/man5/config.html

# [ ca ]
# default_ca      = CA_default            # The default ca section

# [ CA_default ]

# dir             = .                     # top dir
# database        = $dir/index.txt        # index file.
# new_certs_dir   = $dir                  # new certs dir
# certs           = $dir/certs            # Where the issued certs are kept
# certificate     = $dir/ca.pem           # The CA cert
# crl             = $dir/ca.crl           # The current CRL
# crlnumber       = $dir/crlnumber        # the current crl number
# crl_dir         = $dir/crl              # Where the issued crl are kept
# serial          = $dir/serial           # serial number file
# #rand_serial    = yes                   # for random serial#'s
# private_key     = $dir/ca.key		      # CA private key
# RANDFILE        = $dir/.rand  		  # random number file
# default_days    = 365                   # how long to certify for
# default_crl_days= 30                    # how long before next CRL
# default_md      = md5                   # md to use
# policy          = policy_any            # default policy
# email_in_dn     = no                    # Don't add the email into cert DN
# name_opt        = ca_default            # Subject name display option
# cert_opt        = ca_default            # Certificate display option
# copy_extensions = none                  # Don't copy extensions from request


# [ policy_any ]
# countryName            = supplied
# stateOrProvinceName    = optional
# organizationName       = optional
# organizationalUnitName = optional
# commonName             = supplied
# emailAddress           = optional

# [ req ]
# default_bits            = 4096
# default_md              = sha512
# default_keyfile         = privkey.pem
# distinguished_name      = req_distinguished_name
# attributes              = req_attributes
# x509_extensions         = v3_ca
# string_mask             = utf8only

# [ req_distinguished_name ]
# countryName                     = Country Name (2 letter code)
# countryName_default             = SE
# countryName_min                 = 2
# countryName_max                 = 2
# stateOrProvinceName             = State or Province Name (full name)
# stateOrProvinceName_default     = Stockholm
# localityName                    = Locality Name (eg, city)
# localityName_default            = Stockholm
# organizationName                = Organization Name (eg, company)
# organizationName_default        = ACME
# organizationalUnitName          = Organizational Unit Name (eg, section)
# organizationalUnitName_default  = headquater
# commonName                      = Common Name (eg, your name or your servers hostname)
# commonName_default              = ca.demo.com
# commonName_max                  = 64
# emailAddress                    = Email Address
# emailAddress_default            = info@demo.com
# emailAddress_max                = 64

# [ req_attributes ]
# challengePassword               = A challenge password
# challengePassword_min           = 0
# challengePassword_max           = 20
# unstructuredName                = An optional company name

# # Extensions used for RootCA certificate
# [ v3_ca ]  
# subjectKeyIdentifier = hash
# authorityKeyIdentifier = keyid:always,issuer
# basicConstraints = critical,CA:true
# nsComment = "OpenSSL Generated Certificate"

# # Extensions to add to a certificate request
# [ v3_req ]
# basicConstraints = CA:FALSE
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment