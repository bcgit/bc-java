package com.github.gv2011.asn1;

import java.math.BigInteger;

import com.github.gv2011.util.bytes.Bytes;

/**
 * @deprecated Use ASN1Enumerated instead of this.
 */
@Deprecated
public class DEREnumerated
    extends ASN1Enumerated
{
    /**
     * @param bytes the value of this enumerated as an encoded BigInteger (signed).
     * @deprecated use ASN1Enumerated
     */
    @Deprecated
    DEREnumerated(final Bytes bytes)
    {
        super(bytes);
    }

    /**
     * @param value the value of this enumerated.
     * @deprecated use ASN1Enumerated
     */
    @Deprecated
    public DEREnumerated(final BigInteger value)
    {
        super(value);
    }

    /**
     * @param value the value of this enumerated.
     * @deprecated use ASN1Enumerated
     */
    @Deprecated
    public DEREnumerated(final int value)
    {
        super(value);
    }
}
