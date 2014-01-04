package org.bouncycastle.asn1;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

public class ASN1Integer
    extends DERInteger
{
    ASN1Integer(byte[] bytes, boolean clone)
    {
        super(clone ? Arrays.clone(bytes) : bytes);
    }

    /**
     * Constructor from a byte array containing a signed representation of the number.
     *
     * @param bytes a byte array containing the signed number.A copy is made of the byte array.
     */
    public ASN1Integer(byte[] bytes)
    {
        this(bytes, true);
    }

    public ASN1Integer(BigInteger value)
    {
        super(value);
    }

    public ASN1Integer(long value)
    {
        super(value);
    }
}
