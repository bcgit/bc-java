package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * EciesP256EncryptedKey ::= SEQUENCE {
 * v  EccP256CurvePoint,
 * c  OCTET STRING (SIZE (16)),
 * t  OCTET STRING (SIZE (16))
 * }
 */
public class EciesP256EncryptedKey
    extends ASN1Object
{
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
