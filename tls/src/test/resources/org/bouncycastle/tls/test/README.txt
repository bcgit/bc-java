# The key and certificate .pem files here were generated using GnuTLS certtool and the accompanying
# template files.

# CA (signing) credentials:

    certtool --generate-privkey --outfile x509-ca-key-dsa.pem \
        --pkcs8 --password '' --dsa --bits 2048
    certtool --generate-self-signed --template ca.tmpl --outfile x509-ca-dsa.pem \
        --load-privkey x509-ca-key-dsa.pem --hash sha256

    certtool --generate-privkey --outfile x509-ca-key-ecdsa.pem \
        --pkcs8 --password '' --ecdsa --curve secp256r1
    certtool --generate-self-signed --template ca.tmpl --outfile x509-ca-ecdsa.pem \
        --load-privkey x509-ca-key-ecdsa.pem --hash sha256

    certtool --generate-privkey --outfile x509-ca-key-rsa.pem \
        --pkcs8 --password '' --rsa --bits 2048
    certtool --generate-self-signed --template ca.tmpl --outfile x509-ca-rsa.pem \
        --load-privkey x509-ca-key-rsa.pem --hash sha256

# Client agreement credentials:

    certtool --generate-privkey --outfile x509-client-key-ecdh.pem \
        --pkcs8 --password '' --ecc --curve secp256r1
    certtool --generate-certificate --template client_agree.tmpl --outfile x509-client-ecdh.pem \
        --load-privkey x509-client-key-ecdh.pem --hash sha256 \
        --load-ca-privkey x509-ca-key-ecdsa.pem --load-ca-certificate x509-ca-ecdsa.pem

# Client signing credentials:

    certtool --generate-privkey --outfile x509-client-key-dsa.pem \
        --pkcs8 --password '' --dsa --bits 2048
    certtool --generate-certificate --template client_sign.tmpl --outfile x509-client-dsa.pem \
        --load-privkey x509-client-key-dsa.pem --hash sha256 \
        --load-ca-privkey x509-ca-key-dsa.pem --load-ca-certificate x509-ca-dsa.pem

    certtool --generate-privkey --outfile x509-client-key-ecdsa.pem \
        --pkcs8 --password '' --ecdsa --curve secp256r1
    certtool --generate-certificate --template client_sign.tmpl --outfile x509-client-ecdsa.pem \
        --load-privkey x509-client-key-ecdsa.pem --hash sha256 \
        --load-ca-privkey x509-ca-key-ecdsa.pem --load-ca-certificate x509-ca-ecdsa.pem

    certtool --generate-privkey --outfile x509-client-key-rsa.pem \
        --pkcs8 --password '' --rsa --bits 2048
    certtool --generate-certificate --template client_sign.tmpl --outfile x509-client-rsa.pem \
        --load-privkey x509-client-key-rsa.pem --hash sha256 \
        --load-ca-privkey x509-ca-key-rsa.pem --load-ca-certificate x509-ca-rsa.pem

# Server agreement credentials:

    certtool --generate-privkey --outfile x509-server-key-ecdh.pem \
        --pkcs8 --password '' --ecc --curve secp256r1
    certtool --generate-certificate --template server_agree.tmpl --outfile x509-server-ecdh.pem \
        --load-privkey x509-server-key-ecdh.pem --hash sha256 \
        --load-ca-privkey x509-ca-key-ecdsa.pem --load-ca-certificate x509-ca-ecdsa.pem

# Server encryption credentials:

    certtool --generate-privkey --outfile x509-server-key-rsa-enc.pem \
        --pkcs8 --password '' --rsa --bits 2048
    certtool --generate-certificate --outfile x509-server-rsa-enc.pem \
        --load-privkey x509-server-key-rsa-enc.pem --template server_enc.tmpl \
        --load-ca-privkey x509-ca-key-rsa.pem --load-ca-certificate x509-ca-rsa.pem \
        --hash sha256

# Server signing credentials:

    certtool --generate-privkey --outfile x509-server-key-dsa.pem \
        --pkcs8 --password '' --dsa --bits 2048
    certtool --generate-certificate --template server_sign.tmpl --outfile x509-server-dsa.pem \
        --load-privkey x509-server-key-dsa.pem --hash sha256 \
        --load-ca-privkey x509-ca-key-dsa.pem --load-ca-certificate x509-ca-dsa.pem

    certtool --generate-privkey --outfile x509-server-key-ecdsa.pem \
        --pkcs8 --password '' --ecdsa --curve secp256r1
    certtool --generate-certificate --template server_sign.tmpl --outfile x509-server-ecdsa.pem \
        --load-privkey x509-server-key-ecdsa.pem --hash sha256 \
        --load-ca-privkey x509-ca-key-ecdsa.pem --load-ca-certificate x509-ca-ecdsa.pem

    certtool --generate-privkey --outfile x509-server-key-rsa-sign.pem \
        --pkcs8 --password '' --rsa --bits 2048
    certtool --generate-certificate --template server_sign.tmpl --outfile x509-server-rsa-sign.pem \
        --load-privkey x509-server-key-rsa-sign.pem --hash sha256 \
        --load-ca-privkey x509-ca-key-rsa.pem --load-ca-certificate x509-ca-rsa.pem

