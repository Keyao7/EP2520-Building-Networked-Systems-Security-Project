#!/bin/bash

# Make sure ca.key cert-bundle.pem
echo -e "\nInput DIR for CA's cert and certificate chain. (e.g.:/home/usr) Ending with NO slash \"\\\"\n(The CA key must name \"ca.key\". The chain must name \"cert-bundle.pem\". Failed if not found.)"
read -p "Current dir used if omitted:" dir_ca
if [ ! $dir_ca ]; then
	dir_ca="."
fi

if [ -f $dir_ca/ca.key ]; then
	echo "CA Key File Found."
	if [ -f $dir_ca/cert-bundle.pem ]; then
		echo "Chain File Found."
		csplit -z -f $dir_ca/cert- $dir_ca/cert-bundle.pem '/-----BEGIN CERTIFICATE-----/' '{*}'
		mv -f $dir_ca/cert-00 $dir_ca/root.pem
		mv -f $dir_ca/cert-01 $dir_ca/ca.pem
	else
		echo "ERR:Chain File Not Found. Failed!"
		exit 0
	fi
else
	echo "ERR:CA Key File Not Found. Failed!"
	exit 0
fi


# Get name and dir for local key, cert, chain
echo -e "\nInput name for key or certificate file (e.g.:\"server\")"
read -p "Use \"client\" if omitted:" file_name
if [ ! $file_name ]; then
	file_name="client"
else
	file_name=`echo $file_name | sed 's/[[:space:]]//g'`
fi

echo -e "\n\nInput DIR for ${file_name}'s key and generating CSR.\n (The key must name "$file_name.key". If key is not found, it'll be generated.)"
read -p "Current dir used if omitted:" dir_var
if [ ! $dir_var ]
then 
	dir_var="."
fi
mkdir -p $dir_var

if [ -f $dir_var/$file_name.key ]; then
  echo "File \"${file_name}.key\" Found."
else
  echo "File \"${file_name}.key\" Not Found. Generating..."
  openssl genrsa -out $dir_var/$file_name.key 4096
fi

# Generate CSR
echo -e "\n\nIf you have configuration file, make sure it under \"${dir_var}/\".\n (The configuration must name "$file_name.cnf". )"
if [ -f $dir_var/$file_name.cnf ]; then
	echo "File \"${file_name}.cnf\" Found."
	openssl req -new -key $dir_var/$file_name.key -out $dir_var/$file_name.csr -config 
else
	echo "File \"${file_name}.cnf\" Not Found. Use default."
	echo  -e "Default CN:${USER}.demo.com, email:info@demo.com"
	read -p "Input common name (CN), default if omitted:" cn
	if [ ! $cn ]; then 
		cn="${USER}.demo.com"
	fi
	openssl req -new -key $dir_var/$file_name.key -out $dir_var/$file_name.csr -subj "/C=SE/ST=Stockholm/L=Stockholm/O=ACME/OU=Headquarters/CN=$cn/emailAddress=info@demo.com"
fi

# Sign Certificate for local
echo -e "\n\n${file_name}.csr is under \"${dir_var}/\". Sending to CA..."
openssl x509 -req -in $dir_var/$file_name.csr -days 60 -CA $dir_ca/ca.pem -CAkey $dir_ca/ca.key -CAcreateserial -out $dir_var/$file_name.pem
echo -e "\n\n${file_name}.pem is under \"${dir_var}/\". "
chmod g+rw $dir_var/$file_name.pem

# See Certificate
read -p "Type any character to skip seeing certificate \"${file_name}.pem\":" see_cert
if [ ! $see_cert ]; then 
	openssl x509 -in $dir_var/$file_name.pem -noout -text
fi

# Generate new chain
if [ -f $dir_var/cert-bundle_new.pem ]; then
	rm $dir_var/cert-bundle_new.pem
fi
cat $dir_ca/cert-bundle.pem $dir_var/$file_name.pem > $dir_var/cert-bundle_new.pem
chmod g+rw $dir_var/cert-bundle_new.pem
if [ ! -f $dir_var/cert-bundle.pem ]; then
	mv $dir_var/cert-bundle_new.pem $dir_var/cert-bundle.pem
	cert_bundle_path="${dir_var}/cert-bundle.pem"
else
	cert_bundle_path="${dir_var}/cert-bundle_new.pem"
fi
echo "${cert_bundle_path}"
chmod g+rw $cert_bundle_path
openssl verify -CAfile $dir_ca/root.pem $cert_bundle_path


# Generate p12 for client
read -p "Type any character to skip generating \"${file_name}.p12\":" gen_p12
if [ ! $gen_p12 ]; then 
	openssl pkcs12 -export -in $dir_var/$file_name.pem -inkey $dir_var/$file_name.key -CAfile $dir_ca/cert-bundle.pem -name "ACME ${file_name} certificate" -out $dir_var/$file_name.p12
fi

echo "Complete!"