package org.bouncycastle.asn1.its;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *     Signature ::= CHOICE {
 *         ecdsaNistP256Signature EcdsaP256Signature,
 *         ecdsaBrainpoolP256r1Signature EcdsaP256Signature,
 *         ...
 *         ecdsaBrainpoolP384r1Signature EcdsaP384Signature
 *     }
 * </pre>
 */
public class Signature
    extends ASN1Object
    implements ASN1Choice
{
    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
