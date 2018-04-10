package org.bouncycastle.asn1.edcurves;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 *
 * edwards-curves-algs:
 *     draft-ietf-curdle-pkix 
 */
public interface EdwardsCurvesObjectIdentifiers
{
    static final ASN1ObjectIdentifier    edwardsCurvesAlgs       = new ASN1ObjectIdentifier("1.3.101");

    static final ASN1ObjectIdentifier    id_X25519               = edwardsCurvesAlgs.branch("110");
    static final ASN1ObjectIdentifier    id_X448                 = edwardsCurvesAlgs.branch("111");
    static final ASN1ObjectIdentifier    id_Ed25519              = edwardsCurvesAlgs.branch("112");
    static final ASN1ObjectIdentifier    id_Ed448                = edwardsCurvesAlgs.branch("113");
}
