package com.github.gv2011.asn1;

import com.github.gv2011.util.bytes.Bytes;

/**
 * @deprecated use ASN1Boolean
 */
@Deprecated
public class DERBoolean
    extends ASN1Boolean
{
    /**
     * @deprecated use getInstance(boolean) method.
     * @param value
     */
    @Deprecated
    public DERBoolean(final boolean value)
    {
        super(value);
    }

    DERBoolean(final Bytes value)
    {
        super(value);
    }
}
