/**
 * Support for C509 certificates - the CBOR encoding of X.509 certificates, certification
 * requests, certification request templates and private key structures defined in
 * draft-ietf-cose-cbor-encoded-cert-20. Covers both natively signed C509 structures (type 2,
 * signed over the CBOR itself) and invertible CBOR re-encodings of DER X.509 and RFC 2986
 * structures (type 3). This is the layer where CBOR meets the ASN.1 object model: the value
 * types materialize X.500 names, extensions and key/algorithm structures as their
 * org.bouncycastle.asn1 forms, while the underlying org.bouncycastle.cbor codec package stays
 * ASN.1-free. High level holder and builder classes are in org.bouncycastle.cert.c509 in the
 * bcpkix distribution.
 */
package org.bouncycastle.cbor.c509;
