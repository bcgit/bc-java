The key and certificate .pem files here were generated using GnuTLS certtool and the accompanying template files:

    certtool --generate-privkey > x509-ca-key.pem
    certtool --generate-privkey > x509-client-key.pem
    certtool --generate-privkey > x509-server-key.pem
    certtool --generate-self-signed --load-privkey x509-ca-key.pem --template ca.tmpl --outfile x509-ca.pem
    certtool --generate-certificate --load-privkey x509-client-key.pem --load-ca-certificate x509-ca.pem --load-ca-privkey x509-ca-key.pem --template client.tmpl --outfile x509-client.pem
    certtool --generate-certificate --load-privkey x509-server-key.pem --load-ca-certificate x509-ca.pem --load-ca-privkey x509-ca-key.pem --template server.tmpl --outfile x509-server.pem
