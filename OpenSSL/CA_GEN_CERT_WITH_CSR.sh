#!/bin/bash

SERVER_PORT=6666

# Start the netcat server in listen mode
nc -lnv $SERVER_PORT > ~/CA/client/client-req.pem & while true; do

    # Get the client IP address and port number as variables
    client=$(netstat -an | grep $SERVER_PORT | grep 'ESTABLISHED' | awk '{print $5}')

    if [ $client ] then
    client_ip=$(echo $client | awk -F: '{print $1}')
    client_port=$(echo $client | awk -F: '{print $2}')

    # Generate certificatee
    echo -e "Now Generating client's certificate"
    openssl x509 -req -in ~/CA/client/client-req.pem -days 60 -CA ~/CA/ca-cert.pem -CAkey ~/CA/ca-key.pem -CAcreateserial -out ~/CA/client/client-cert.pem
    
    # Send the modified file back to the client
    echo "Sending modified file back to client..."
    nc $CLIENT_IP $CLIENT_PORT < ~/CA/client/client-cert.pem
    fi
done