# Setup secret key
openssl genpkey -algorithm ed25519 -out secret_key.pem

# Extract PK from SK
openssl pkey -pubout -in secret_key.pem -out public-key.pem