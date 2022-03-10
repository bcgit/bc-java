package org.bouncycastle.oer.its.etsi102941.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

public class Version
    extends ASN1Object
{
    private final BigInteger version;

    public Version(BigInteger value)
    {
        this.version = value;
    }

    public Version(int value)
    {
        this(BigInteger.valueOf(value));
    }

    public Version(long value)
    {
        this(BigInteger.valueOf(value));
    }

    protected Version(ASN1Integer integer)
    {
        this.version = integer.getValue();
    }

    public BigInteger getVersion()
    {
        return version;
    }

    public static Version getInstance(Object o)
    {
        if (o instanceof UINT8)
        {
            return (Version)o;
        }

        if (o != null)
        {
            return new Version(ASN1Integer.getInstance(o));
        }

        return null;
    }


    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(version);
    }
}
