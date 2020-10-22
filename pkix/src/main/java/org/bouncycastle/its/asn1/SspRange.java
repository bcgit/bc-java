package org.bouncycastle.its.asn1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;

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
{
    private final boolean isAll;
    private final SequenceOfOctetString opaque;
    private final BitmapSspRange bitmapSspRange;

    private SspRange()
    {
        isAll = true;
        opaque = null;
        bitmapSspRange = null;
    }

    private SspRange(SequenceOfOctetString seq)
    {
        this.isAll = false;
        if (seq.size() != 2)
        {
            opaque = seq;
            bitmapSspRange = null;
        }
        else
        {
            // ambiguous
            opaque = SequenceOfOctetString.getInstance(seq);

            BitmapSspRange bitMapRange;
            try
            {
                bitMapRange = BitmapSspRange.getInstance(seq);
            }
            catch (IllegalArgumentException e)
            {
                bitMapRange = null;
            }

            bitmapSspRange = bitMapRange;
        }
    }

    public SspRange(BitmapSspRange range)
    {
        this.isAll = false;
        this.bitmapSspRange = range;
        this.opaque = null;
    }

    public static SspRange getInstance(Object src)
    {
        if (src == null)
        {
            return null;
        }

        if (src instanceof SspRange)
        {
            return (SspRange)src;
        }

        if (src instanceof ASN1Null)
        {
            return new SspRange();
        }

        if (src instanceof ASN1Sequence)
        {
            return new SspRange(SequenceOfOctetString.getInstance(src));
        }

        if (src instanceof byte[])
        {
            try
            {
                return getInstance(ASN1Primitive.fromByteArray((byte[])src));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("unable to parse encoded general name");
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + src.getClass().getName());
    }

    public boolean isAll()
    {
        return isAll;
    }

    public boolean maybeOpaque()
    {
        return opaque != null;
    }

    public BitmapSspRange getBitmapSspRange()
    {
        return bitmapSspRange;
    }

    public SequenceOfOctetString getOpaque()
    {
        return opaque;
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (isAll)
        {
            return DERNull.INSTANCE;
        }

        if (bitmapSspRange != null)
        {
            return bitmapSspRange.toASN1Primitive();
        }

        return opaque.toASN1Primitive();
    }
}
