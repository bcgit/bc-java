package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * EcdsaP384Signature ::= SEQUENCE {
 * rSig  EccP384CurvePoint,
 * sSig  OCTET STRING (SIZE (48))
 * }
 */
public class EcdsaP384Signature
    extends ASN1Object
{
    private final EccP384CurvePoint rSig;
    private final ASN1OctetString sSig;

    public EcdsaP384Signature(EccP384CurvePoint rSig, ASN1OctetString sSig)
    {
        this.rSig = rSig;
        this.sSig = sSig;
    }

    public static EcdsaP384Signature getInstance(Object object)
    {
        ASN1Sequence it = ASN1Sequence.getInstance(object);

        return new Builder()
            .setrSig(EccP384CurvePoint.getInstance(it.getObjectAt(0)))
            .setsSig(ASN1OctetString.getInstance(it.getObjectAt(1)))
            .createEcdsaP384Signature();

    }

    public EccP384CurvePoint getrSig()
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


        private EccP384CurvePoint rSig;
        private ASN1OctetString sSig;

        public Builder setrSig(EccP384CurvePoint rSig)
        {
            this.rSig = rSig;
            return this;
        }

        public Builder setsSig(ASN1OctetString sSig)
        {
            this.sSig = sSig;
            return this;
        }

        public EcdsaP384Signature createEcdsaP384Signature()
        {
            return new EcdsaP384Signature(rSig, sSig);
        }
    }
}
