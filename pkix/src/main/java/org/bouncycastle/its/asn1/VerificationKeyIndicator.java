package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *     VerificationKeyIndicator ::= CHOICE {
 *         verificationKey PublicVerificationKey,
 *         reconstructionValue EccP256CurvePoint,
 *         ...
 *     }
 * </pre>
 */
public class VerificationKeyIndicator
    extends ASN1Object
    implements ASN1Choice
{
    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}