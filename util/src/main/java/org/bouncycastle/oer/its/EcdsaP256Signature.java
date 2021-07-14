package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * EcdsaP256Signature ::= SEQUENCE {
 * rSig  EccP256CurvePoint,
 * sSig  OCTET STRING (SIZE (32))
 * }
 */
public class EcdsaP256Signature
    extends ASN1Object
{
    private final EccP256CurvePoint rSig;
    private final ASN1OctetString sSig;

    public EcdsaP256Signature(EccP256CurvePoint rSig, ASN1OctetString sSig)
    {
        this.rSig = rSig;
        this.sSig = sSig;
    }

    public static EcdsaP256Signature getInstance(Object object)
    {
        ASN1Sequence it = ASN1Sequence.getInstance(object);

        return new Builder()
            .setrSig(EccP256CurvePoint.getInstance(it.getObjectAt(0)))
            .setsSig(ASN1OctetString.getInstance(it.getObjectAt(1)))
            .createEcdsaP256Signature();
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public EccP256CurvePoint getrSig()
    {
        return rSig;
    }

    public ASN1OctetString getsSig()
    {
        return sSig;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(rSig, sSig);
    }

    public static class Builder
    {
        private EccP256CurvePoint rSig;
        private ASN1OctetString sSig;

        public Builder setrSig(EccP256CurvePoint rSig)
        {
            this.rSig = rSig;
            return this;
        }

        public Builder setsSig(ASN1OctetString sSig)
        {
            this.sSig = sSig;
            return this;
        }

        public EcdsaP256Signature createEcdsaP256Signature()
        {
            return new EcdsaP256Signature(rSig, sSig);
        }
    }
}
