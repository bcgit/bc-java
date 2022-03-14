package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

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
    private final EccP256CurvePoint v;
    private final ASN1OctetString c;
    private final ASN1OctetString t;

    public EciesP256EncryptedKey(EccP256CurvePoint v, ASN1OctetString c, ASN1OctetString t)
    {
        this.v = v;
        this.c = c;
        this.t = t;
    }

    public static EciesP256EncryptedKey getInstance(Object o)
    {
        if (o instanceof EciesP256EncryptedKey)
        {
            return (EciesP256EncryptedKey)o;
        }
        if (o != null)
        {
            return new EciesP256EncryptedKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private EciesP256EncryptedKey(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("expected sequence size of 3");
        }

        v = EccP256CurvePoint.getInstance(seq.getObjectAt(0));
        c = ASN1OctetString.getInstance(seq.getObjectAt(1));
        t = ASN1OctetString.getInstance(seq.getObjectAt(2));

    }

    public EccP256CurvePoint getV()
    {
        return v;
    }

    public ASN1OctetString getC()
    {
        return c;
    }

    public ASN1OctetString getT()
    {
        return t;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{v, c, t});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private EccP256CurvePoint v;
        private ASN1OctetString c;
        private ASN1OctetString t;

        public Builder setV(EccP256CurvePoint v)
        {
            this.v = v;
            return this;
        }

        public Builder setC(ASN1OctetString c)
        {
            this.c = c;
            return this;
        }


        public Builder setC(byte[] c)
        {
            this.c = new DEROctetString(Arrays.clone(c));
            return this;
        }


        public Builder setT(ASN1OctetString t)
        {
            this.t = t;
            return this;
        }

        public Builder setT(byte[] t)
        {
            this.t = new DEROctetString(Arrays.clone(t));
            return this;
        }

        public EciesP256EncryptedKey createEciesP256EncryptedKey()
        {
            return new EciesP256EncryptedKey(v, c, t);
        }
    }

}
