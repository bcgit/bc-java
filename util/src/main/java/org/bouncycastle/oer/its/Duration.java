package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 *     Duration ::= CHOICE {
 *         microseconds Uint16,
 *         milliseconds Uint16,
 *         seconds Uint16,
 *         minutes Uint16,
 *         hours Uint16,
 *         sixtyHours Uint16,
 *         years Uint16
 *     }
 * </pre>
 */
public class Duration
    extends ASN1Object
    implements ASN1Choice
{
    public static final int microseconds = 0;
    public static final int milliseconds = 1;
    public static final int seconds = 2;
    public static final int minutes = 3;
    public static final int hours = 4;
    public static final int sixtyHours = 5;
    public static final int years = 6;

    private final int tag;
    private final int value;

    public Duration(int tag, int value)
    {
        this.tag = tag;
        this.value = value;
    }

    public static Duration getInstance(Object o)
    {
        if (o instanceof Duration)
        {
            return (Duration)o;
        }
        else
        {
            ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(o);
            int choice = taggedObject.getTagNo();
            switch (choice)
            {
            case microseconds:
            case milliseconds:
            case seconds:
            case minutes:
            case hours:
            case sixtyHours:
            case years:
                try
                {
                    return new Duration(choice, ASN1Integer.getInstance(taggedObject.getObject()).getValue().intValue());
                }
                catch (Exception ioex)
                {
                    throw new IllegalStateException(ioex.getMessage(), ioex);
                }
            default:
                throw new IllegalArgumentException("invalid choice value " + choice);
            }
        }

    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(tag, new ASN1Integer(value));
    }

    public int getTag()
    {
        return tag;
    }

    public int getValue()
    {
        return value;
    }
}
