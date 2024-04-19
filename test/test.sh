#!/bin/bash

comment

#Scans for open ports on localhost, 27 ports should be scanned
nc -zv localhost 1-10255

#GET request to the server, should return 200 OK
curl http://localhost:80/admin 

#POST request to the server
#1. Sends a txt file
curl -X POST --data-binary @test.txt  http://localhost:80
#2. Sends a pdf file
curl -X POST --data-binary @test.pdf  http://localhost:80
#3. Sends a file over 100MB
curl -X POST --data-binary @test.mbox.zip  http://localhost:80

# postgresql login attempt
#psql -h 127.0.0.1 -p 5432 -U admin 'sslmode=disable'

# ssl login attempt
#ssh -o StrictHostKeyChecking=no -p2023 attacker1@localhost


