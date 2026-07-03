#!/bin/bash
# NextPATH P2P Sync TLS Certificate Generator

set -e

CERT_DIR="./certs"
CERT_FILE="${CERT_DIR}/cert.pem"
KEY_FILE="${CERT_DIR}/key.pem"

echo "Generating self-signed TLS certificates for NextPATH P2P Sync..."

mkdir -p "$CERT_DIR"

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=NextPATH-P2P" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo "Certificates generated successfully!"
echo "Cert: $CERT_FILE"
echo "Key: $KEY_FILE"
echo ""
echo "To use these certificates in cluster mode, mount the certs directory to the container:"
echo "Volumes section in docker-compose.yml:"
echo "    volumes:"
echo "      - ./certs:/app/nextpath/certs:ro"
