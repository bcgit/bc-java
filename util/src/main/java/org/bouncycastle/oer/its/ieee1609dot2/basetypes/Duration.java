package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
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

    private final int choice;
    private final UINT16 duration;

    public Duration(int tag, UINT16 value)
    {
        this.choice = tag;
        this.duration = value;
    }

    private Duration(ASN1TaggedObject taggedObject)
    {
        choice = taggedObject.getTagNo();
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
                duration = UINT16.getInstance(taggedObject.getExplicitBaseObject());
            }
            catch (Exception ioex)
            {
                throw new IllegalStateException(ioex.getMessage(), ioex);
            }
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
    }

    public static Duration getInstance(Object o)
    {
        if (o instanceof Duration)
        {
            return (Duration)o;
        }

        if (o != null)
        {
            return new Duration(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;

    }

    public static Duration years(UINT16 value)
    {
        return new Duration(years, value);
    }

    public static Duration sixtyHours(UINT16 value)
    {
        return new Duration(sixtyHours, value);
    }

    public static Duration hours(UINT16 value)
    {
        return new Duration(hours, value);
    }

    public static Duration minutes(UINT16 value)
    {
        return new Duration(minutes, value);
    }

    public static Duration seconds(UINT16 value)
    {
        return new Duration(seconds, value);
    }

    public static Duration milliseconds(UINT16 value)
    {
        return new Duration(milliseconds, value);
    }

    public static Duration microseconds(UINT16 value)
    {
        return new Duration(microseconds, value);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, duration);
    }

    public int getChoice()
    {
        return choice;
    }

    public UINT16 getDuration()
    {
        return duration;
    }

    @Override
    public String toString()
    {
        switch (choice)
        {
        case microseconds:
            return duration.value + "uS";
        case milliseconds:
            return duration.value + "mS";
        case seconds:
            return duration.value + " seconds";
        case minutes:
            return duration.value + " minute";
        case hours:
            return duration.value + " hours";
        case sixtyHours:
            return duration.value + " sixty hours";
        case years:
            return duration.value + " years";
        default:
            return duration.value + " unknown choice";
        }
    }
}
