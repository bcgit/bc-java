package org.bouncycastle.oer.its.etsi103097.extension;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

/**
 * ExtId ::= INTEGER(0..255)
 */
public class ExtId
    extends ASN1Integer
{

    public ExtId(long value)
    {
        super(value);
        if (value < 0 || value > 255)
        {
            throw new IllegalArgumentException("value " + value + " outside of range 0...255");
        }
    }


    public ExtId(BigInteger value)
    {
        super(value);
        if (getValue().intValue() < 0 || getValue().intValue() > 255)
        {
            throw new IllegalArgumentException("value " + getValue() + " outside of range 0...255");
        }
    }

    public ExtId(byte[] bytes)
    {
        super(bytes);
        if (getValue().intValue() < 0 || getValue().intValue() > 255)
        {
            throw new IllegalArgumentException("value " + getValue() + " outside of range 0...255");
        }
    }

    public static ExtId getInstance(Object object)
    {
        if (object instanceof ExtId)
        {
            return (ExtId)object;
        }

        if (object != null)
        {
            return new ExtId(ASN1Integer.getInstance(object).getValue());
        }

        return null;
    }
}
