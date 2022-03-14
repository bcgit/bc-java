package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.util.Arrays;

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

    private EcdsaP384Signature(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        rSig = EccP384CurvePoint.getInstance(sequence.getObjectAt(0));
        sSig = ASN1OctetString.getInstance(sequence.getObjectAt(1));
    }

    public static EcdsaP384Signature getInstance(Object object)
    {

        if (object instanceof EcdsaP384Signature)
        {
            return (EcdsaP384Signature)object;
        }

        if (object != null)
        {
            return new EcdsaP384Signature(ASN1Sequence.getInstance(object));
        }

        return null;
    }

    public EccP384CurvePoint getRSig()
    {
        return rSig;
    }

    public ASN1OctetString getSSig()
    {
        return sSig;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(rSig, sSig);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {


        private EccP384CurvePoint rSig;
        private ASN1OctetString sSig;

        public Builder setRSig(EccP384CurvePoint rSig)
        {
            this.rSig = rSig;
            return this;
        }

        public Builder setSSig(ASN1OctetString sSig)
        {
            this.sSig = sSig;
            return this;
        }

        public Builder setSSig(byte[] sSig)
        {
            return setSSig(new DEROctetString(Arrays.clone(sSig)));
        }

        public EcdsaP384Signature createEcdsaP384Signature()
        {
            return new EcdsaP384Signature(rSig, sSig);
        }
    }
}
