#! /bin/sh

outdir=src/main/resources
outbase=jwt-signing
private=$outdir/$outbase-private.pem
public=$outdir/$outbase-public.pem

# generate the keys
openssl genpkey -algorithm RSA -out $private -pkeyopt rsa_keygen_bits:2048 

# extract the public key
openssl rsa -pubout -in $private -out $public
