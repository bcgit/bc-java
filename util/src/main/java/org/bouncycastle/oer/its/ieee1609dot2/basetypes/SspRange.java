package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 * SspRange ::= CHOICE {
 *     opaque SequenceOfOctetString,
 *     all NULL,
 *     ...
 *     bitmapSspRange BitmapSspRange
 * }
 * </pre>
 */
public class SspRange
    extends ASN1Object
    implements ASN1Choice
{

    public static final int opaque = 0;
    public static final int all = 1;
    public static final int bitmapSspRange = 2;

    private final int choice;
    private final ASN1Encodable sspRange;

    public static SspRange opaque(SequenceOfOctetString bytes)
    {
        return new SspRange(opaque, bytes);
    }

    public static SspRange all()
    {
        return new SspRange(all, DERNull.INSTANCE);
    }


    public static SspRange bitmapSspRange(BitmapSspRange ext)
    {
        return new SspRange(bitmapSspRange, ext);
    }


    public SspRange(int choice, ASN1Encodable value)
    {

        switch (choice)
        {
        case opaque:
        case all:
        case bitmapSspRange:
            break;
        default:
            throw new IllegalArgumentException("invalid choice value "+choice);
        }


        this.choice = choice;
        this.sspRange = value;
    }


    private SspRange(ASN1TaggedObject ato)
    {
        this(ato.getTagNo(), ato.getExplicitBaseObject());
    }


    public static SspRange getInstance(Object src)
    {
        if (src instanceof SspRange)
        {
            return (SspRange)src;
        }

        if (src != null)
        {
            return new SspRange(ASN1TaggedObject.getInstance(src, BERTags.CONTEXT_SPECIFIC));
        }

        return null;

    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getSspRange()
    {
        return sspRange;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, sspRange);
    }


}
