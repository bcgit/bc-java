package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.util.Arrays;

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

    private EcdsaP256Signature(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.rSig = EccP256CurvePoint.getInstance(sequence.getObjectAt(0));
        this.sSig = ASN1OctetString.getInstance(sequence.getObjectAt(1));
    }

    public static EcdsaP256Signature getInstance(Object object)
    {
        if (object instanceof EcdsaP256Signature)
        {
            return (EcdsaP256Signature)object;
        }
        if (object != null)
        {
            return new EcdsaP256Signature(ASN1Sequence.getInstance(object));
        }
        return null;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public EccP256CurvePoint getRSig()
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

    public static class Builder
    {
        private EccP256CurvePoint rSig;
        private ASN1OctetString sSig;

        public Builder setRSig(EccP256CurvePoint rSig)
        {
            this.rSig = rSig;
            return this;
        }

        public Builder setSSig(byte[] sSig)
        {
            this.sSig = new DEROctetString(Arrays.clone(sSig));
            return this;
        }

        public Builder setSSig(ASN1OctetString sSig)
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
