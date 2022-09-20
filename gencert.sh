#!/bin/bash -eux

openssl req \
	-nodes \
	-subj '/CN=localhost' \
	-x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365
