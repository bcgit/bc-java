package org.bouncycastle.oer.its.etsi103097.extension;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * ExtId ::= INTEGER(0..255)
 */
public class ExtId
    extends ASN1Object
{
    private final BigInteger extId;

    private static final BigInteger MAX = BigInteger.valueOf(255);

    public ExtId(long value)
    {
        this(BigInteger.valueOf(value));
    }

    public ExtId(BigInteger value)
    {
        if (value.signum() < 0 || value.compareTo(MAX) > 0)
        {
            throw new IllegalArgumentException("value " + value + " outside of range 0...255");
        }
        this.extId = value;
    }

    public ExtId(byte[] bytes)
    {
        this(new BigInteger(bytes));
    }

    private ExtId(ASN1Integer integer)
    {
        this(integer.getValue());
    }

    public BigInteger getExtId()
    {
        return extId;
    }

    public static ExtId getInstance(Object object)
    {
        if (object instanceof ExtId)
        {
            return (ExtId)object;
        }

        if (object != null)
        {
            return new ExtId(ASN1Integer.getInstance(object));
        }

        return null;
    }


    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(extId);
    }
}
