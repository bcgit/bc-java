package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.BigIntegers;

public class Point384
    extends ASN1Object
{
    private final ASN1OctetString x;
    private final ASN1OctetString y;

    public Point384(ASN1OctetString x, ASN1OctetString y)
    {
        if (x.getOctets().length != 48)
        {
            throw new IllegalArgumentException("x must be 48 bytes long");
        }

        if (y.getOctets().length != 48)
        {
            throw new IllegalArgumentException("y must be 48 bytes long");
        }

        this.x = x;
        this.y = y;
    }

    private Point384(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        x = ASN1OctetString.getInstance(seq.getObjectAt(0));
        y = ASN1OctetString.getInstance(seq.getObjectAt(1));

        if (x.getOctets().length != 48)
        {
            throw new IllegalArgumentException("x must be 48 bytes long");
        }

        if (y.getOctets().length != 48)
        {
            throw new IllegalArgumentException("y must be 48 bytes long");
        }

    }

    public static Point384 getInstance(Object o)
    {
        if (o instanceof Point384)
        {
            return (Point384)o;
        }

        if (o != null)
        {
            return new Point384(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    public ASN1OctetString getX()
    {
        return x;
    }

    public ASN1OctetString getY()
    {
        return y;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{
            x, y
        });
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private ASN1OctetString x;
        private ASN1OctetString y;

        public Builder setX(ASN1OctetString x)
        {
            this.x = x;
            return this;
        }

        public Builder setX(byte[] x)
        {
            this.x = new DEROctetString(x);
            return this;
        }

        public Builder setX(BigInteger x)
        {
            this.x = new DEROctetString(BigIntegers.asUnsignedByteArray(48, x));
            return this;
        }


        public Builder setY(ASN1OctetString y)
        {
            this.y = y;
            return this;
        }

        public Builder setY(byte[] y)
        {
            this.y = new DEROctetString(y);
            return this;
        }

        public Builder setY(BigInteger y)
        {
            this.y = new DEROctetString(BigIntegers.asUnsignedByteArray(48, y));
            return this;
        }

        //BigIntegers.asUnsignedByteArray(48, x)

        public Point384 createPoint384()
        {
            return new Point384(x, y);
        }

    }

}
