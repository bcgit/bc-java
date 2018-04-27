package org.bouncycastle.asn1.rfc7748;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 *
 * Reference: draft-ietf-curdle-pkix
 * <pre>
 * id-X25519    OBJECT IDENTIFIER ::= { 1 3 101 110 }
 * id-X448      OBJECT IDENTIFIER ::= { 1 3 101 111 }
 * id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
 * id-Ed448     OBJECT IDENTIFIER ::= { 1 3 101 113 }
 * </pre> 
 */
public interface RFC7748ObjectIdentifiers
{
    static final ASN1ObjectIdentifier    id_X25519               = new ASN1ObjectIdentifier("1.3.101.110");
    static final ASN1ObjectIdentifier    id_X448                 = new ASN1ObjectIdentifier("1.3.101.111");
    static final ASN1ObjectIdentifier    id_Ed25519              = new ASN1ObjectIdentifier("1.3.101.112");
    static final ASN1ObjectIdentifier    id_Ed448                = new ASN1ObjectIdentifier("1.3.101.113");
}
