package com.github.gv2011.asn1;

import java.math.BigInteger;

import com.github.gv2011.util.bytes.Bytes;

/**
 * @deprecated  Use ASN1Integer instead of this,
 */
@Deprecated
public class DERInteger
    extends ASN1Integer
{
    /**
     * Constructor from a byte array containing a signed representation of the number.
     *
     * @param bytes a byte array containing the signed number.A copy is made of the byte array.
     */
    public DERInteger(final Bytes bytes)
    {
        super(bytes);
    }

    public DERInteger(final BigInteger value)
    {
        super(value);
    }

    public DERInteger(final long value)
    {
        super(value);
    }
}
