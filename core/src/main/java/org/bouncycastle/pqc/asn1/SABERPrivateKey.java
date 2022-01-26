package org.bouncycastle.pqc.asn1;


import org.bouncycastle.asn1.ASN1Object;

/**
 *
 *    SABERPrivateKey ::= SEQUENCE {
 *        version     INTEGER  {v0(0)}    -- version (round 3)
 *        z           OCTET STRING,       -- 32-byte random value z
 *        s           OCTET STRING,       -- short integer polynomial s
 *        PublicKey   [0] IMPLICIT SABERPublicKey OPTIONAL,
 *                                        -- see next section
 *        hpk         OCTET STRING        -- H(pk)
 *    }
 *
 */
public class SABERPrivateKey
    extends ASN1Object
{
    private int version;
    private byte[] z;
    private byte[] s;
    private byte[] hpk;
}
