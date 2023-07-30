#!/bin/bash

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -x509 -nodes -days 3650 -out p256_cert.pem -keyout p256_key.pem -subj "/C=ch/ST=Bern/L=Lyss/O=p256/CN=allerate.ch"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -x509 -nodes -days 3650 -out p384_cert.pem -keyout p384_key.pem -subj "/C=ch/ST=Bern/L=Lyss/O=p384/CN=allerate.ch"

openssl ec -in p256_key.pem -outform DER -out p256_key.der
openssl ec -in p384_key.pem -outform DER -out p384_key.der

openssl ec -in p256_key.pem -pubout -outform DER -out p256_public_key.der
openssl ec -in p384_key.pem -pubout -outform DER -out p384_public_key.der

openssl ec -in p256_key.pem -no_public -outform DER -out p256_private_key.der
openssl ec -in p384_key.pem -no_public -outform DER -out p384_private_key.der



