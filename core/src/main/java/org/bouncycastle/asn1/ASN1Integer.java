package org.bouncycastle.asn1;

import java.math.BigInteger;

/**
 * This is ASN.1 INTEGER public facade.
 */

public class ASN1Integer
    extends DERInteger
{
    ASN1Integer(byte[] bytes)
    {
        super(bytes);
    }

    /**
     * Construct ASN.1 Integer from BigInteger.
     */
    public ASN1Integer(BigInteger value)
    {
        super(value);
    }

    /**
     * Construct ASN.1 Integer from long.
     */
    public ASN1Integer(long value)
    {
        super(value);
    }
}
