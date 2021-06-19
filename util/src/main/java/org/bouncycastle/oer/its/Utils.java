package org.bouncycastle.oer.its;

import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

class Utils
{
    /**
     * <pre>
     *     OCTET STRING (SIZE(n))
     * </pre>
     */
    static byte[] octetStringFixed(byte[] octets, int n)
    {
        if (octets.length != n)
        {
            throw new IllegalArgumentException("octet string out of range");
        }

        return octets;
    }

    /**
     * <pre>
     *     OCTET STRING (SIZE(1..32))
     * </pre>
     */
    static byte[] octetStringFixed(byte[] octets)
    {
        if (octets.length < 1 || octets.length > 32)
        {
            throw new IllegalArgumentException("octet string out of range");
        }

        return Arrays.clone(octets);
    }

    static ASN1Sequence toSequence(List objs)
    {
        return new DERSequence((ASN1Encodable[])objs.toArray(new ASN1Encodable[objs.size()]));
    }

    static ASN1Sequence toSequence(ASN1Encodable... objs)
    {
        return new DERSequence(objs);
    }

    static List<TwoDLocation> toList(ASN1Sequence instance, Class<TwoDLocation> twoDLocationClass)
    {
        return null;
    }
}
