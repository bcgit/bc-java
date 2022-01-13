package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class GenRepContent
    extends ASN1Object
{
    private final ASN1Sequence content;

    private GenRepContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public GenRepContent(InfoTypeAndValue itv)
    {
        content = new DERSequence(itv);
    }

    public GenRepContent(InfoTypeAndValue[] itvs)
    {
        content = new DERSequence(itvs);
    }

    public static GenRepContent getInstance(Object o)
    {
        if (o instanceof GenRepContent)
        {
            return (GenRepContent)o;
        }

        if (o != null)
        {
            return new GenRepContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public InfoTypeAndValue[] toInfoTypeAndValueArray()
    {
        InfoTypeAndValue[] result = new InfoTypeAndValue[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = InfoTypeAndValue.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * GenRepContent ::= SEQUENCE OF InfoTypeAndValue
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
