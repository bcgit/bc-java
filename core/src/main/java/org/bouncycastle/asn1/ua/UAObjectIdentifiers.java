package org.bouncycastle.asn1.ua;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface UAObjectIdentifiers
{
    // Ukrainian object identifiers
    // {iso(1) member-body(2) Ukraine(804 ) root(2) security(1) cryptography(1) pki(1)}

    static final ASN1ObjectIdentifier UaOid = new ASN1ObjectIdentifier("1.2.804.2.1.1.1");

    // {pki-alg(1) pki-alg-�sym(3) Dstu4145WithGost34311(1) PB(1)}
    // DSTU4145 in polynomial basis has 2 oids, one for little-endian representation and one for big-endian
    static final ASN1ObjectIdentifier dstu4145le = UaOid.branch("1.3.1.1");
    static final ASN1ObjectIdentifier dstu4145be = UaOid.branch("1.3.1.1.1.1");
}
