package com.github.gv2011.asn1;

import com.github.gv2011.util.bytes.Bytes;

/**
 *
 * @deprecated Use ASN1ObjectIdentifier instead of this,
 */
@Deprecated
public class DERObjectIdentifier
    extends ASN1ObjectIdentifier
{
    public DERObjectIdentifier(final String identifier)
    {
        super(identifier);
    }

    DERObjectIdentifier(final Bytes bytes)
    {
        super(bytes);
    }

    DERObjectIdentifier(final ASN1ObjectIdentifier oid, final String branch)
    {
        super(oid, branch);
    }
}
