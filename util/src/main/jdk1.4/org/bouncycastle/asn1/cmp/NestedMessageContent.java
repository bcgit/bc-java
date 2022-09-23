package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Sequence;

/**
 * NestedMessageContent ::= PKIMessages
 */
public class NestedMessageContent
    extends PKIMessages
{
    public NestedMessageContent(PKIMessage msg)
    {
        super(msg);
    }

    public NestedMessageContent(PKIMessage[] msgs)
    {
        super(msgs);
    }

    public NestedMessageContent(ASN1Sequence seq)
    {
        super(seq);
    }

    public static PKIMessages getInstance(Object o)
    {
        if (o instanceof NestedMessageContent)
        {
            return (NestedMessageContent)o;
        }

        if (o != null)
        {
            return new NestedMessageContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }


}
