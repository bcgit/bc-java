package org.bouncycastle.oer.its;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

/**
 * CrlSeries ::= Uint16
 */
public class CrlSeries
    extends Uint16
{
    public CrlSeries(long value)
    {
        super(value);
        assertRange();
    }

    public CrlSeries(BigInteger value)
    {
        super(value);
        assertRange();
    }

    public CrlSeries(byte[] bytes)
    {
        super(bytes);
        assertRange();
    }

    private void assertRange()
    {
        if (BigInteger.ZERO.compareTo(getValue()) > 0 || BigInteger.valueOf(0xFFFF).compareTo(getValue()) < 0)
        {
            throw new IllegalStateException("value must be >=0 && < 0xFFFF");
        }
    }


    public static CrlSeries getInstance(Object o)
    {
        if (o instanceof CrlSeries)
        {
            return (CrlSeries)o;
        }
        return new CrlSeries(ASN1Integer.getInstance(o).getValue());

    }

}
