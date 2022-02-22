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

public class Point256
    extends ASN1Object
{
    private final ASN1OctetString x;
    private final ASN1OctetString y;

    public Point256(ASN1OctetString x, ASN1OctetString y)
    {
        if (x == null || x.getOctets().length != 32)
        {
            throw new IllegalArgumentException("x must be 32 bytes long");
        }

        if (y == null || y.getOctets().length != 32)
        {
            throw new IllegalArgumentException("y must be 32 bytes long");
        }

        this.x = x;
        this.y = y;
    }

    private Point256(ASN1Sequence instance)
    {
        if (instance.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        x = ASN1OctetString.getInstance(instance.getObjectAt(0));
        y = ASN1OctetString.getInstance(instance.getObjectAt(1));

        if (x.getOctets().length != 32)
        {
            throw new IllegalArgumentException("x must be 32 bytes long");
        }

        if (y.getOctets().length != 32)
        {
            throw new IllegalArgumentException("y must be 32 bytes long");
        }
    }

    public static Point256 getInstance(Object object)
    {
        if (object instanceof Point256)
        {
            return (Point256)object;
        }
        if (object != null)
        {
            return new Point256(ASN1Sequence.getInstance(object));
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

        public Builder setY(ASN1OctetString y)
        {
            this.y = y;
            return this;
        }


        public Builder setX(byte[] x)
        {
            this.x = new DEROctetString(x);
            return this;
        }

        public Builder setY(byte[] y)
        {
            this.y = new DEROctetString(y);
            return this;
        }

        public Builder setX(BigInteger x)
        {
            return setX(BigIntegers.asUnsignedByteArray(32, x));
        }

        public Builder setY(BigInteger y)
        {
            return setY(BigIntegers.asUnsignedByteArray(32, y));
        }


        public Point256 createPoint256()
        {
            return new Point256(x, y);
        }

    }

}
