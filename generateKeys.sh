#!/bin/bash

mkdir -p ~/.eft
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ~/.eft/cert.pem
openssl rsa -pubout -in ~/.eft/cert.pem -out ~/.eft/cert.pub