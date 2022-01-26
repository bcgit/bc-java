package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.Arrays;

/**
 * LinkageSeed ::= OCTET STRING (SIZE(16))
 */
public class LinkageSeed
    extends ASN1Object
{
    private final byte[] linkageSeed;

    public LinkageSeed(byte[] linkageSeed)
    {
        if (linkageSeed.length != 16)
        {
            throw new IllegalArgumentException("linkage seed not 16 bytes");
        }
        this.linkageSeed = Arrays.clone(linkageSeed);
    }

    private LinkageSeed(ASN1OctetString value)
    {
        this(value.getOctets());
    }

    public static LinkageSeed getInstance(Object o)
    {
        if (o instanceof LinkageSeed)
        {
            return (LinkageSeed)o;
        }
        if (o != null)
        {
            return new LinkageSeed(DEROctetString.getInstance(o));
        }
        return null;
    }

    public byte[] getLinkageSeed()
    {
        return linkageSeed;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(linkageSeed);
    }
}
