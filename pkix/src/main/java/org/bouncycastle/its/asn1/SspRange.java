package org.bouncycastle.its.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;

public class SspRange extends ASN1Object
{
    private ASN1Sequence opaque;
    private ASN1Null all;
    private BitmapSspRange bitmapSspRange;

    public static SspRange getInstance(Object src)
    {
        if (src == null)
        {
            return null;
        }
        else if (src instanceof SspRange)
        {
            return (SspRange)src;
        }
        else if (src instanceof ASN1InputStream)
        {
            try
            {
                SspRange range = new SspRange();
                Object o = ((ASN1InputStream)src).readObject();
                if (o instanceof ASN1Null)
                {
                    range.setAll();
                }
                else if (o instanceof ASN1Sequence)
                {
                    if (((ASN1Sequence)o).size() == 2)
                    {

                        /*
                        There is ambiguity here:

                        SspRange ::= CHOICE {
                            opaque SequenceOfOctetString,
                            all NULL,
                            ... ,
                        bitmapSspRange BitmapSspRange
                        }

                        BitmapSspRange ::= SEQUENCE {
                            sspValue OCTET STRING (SIZE(1..32)),
                            sspBitmask OCTET STRING (SIZE(1..32))
                        }
                        SequenceOfOctetString ::= SEQUENCE (SIZE (0..MAX)) OF
                         OCTET STRING (SIZE(0..MAX))

                       SequenceOfOctetString could be confused with BitmapSspRange so if there are two
                       octet strings and they are less than 32 elements we set both "opaque" and BitMapSspRange.

                         */

                        for (int t = 0; t < ((ASN1Sequence)o).size(); t++)
                        {
                            ASN1Encodable item = ((ASN1Sequence)o).getObjectAt(t);
                            if (item instanceof ASN1OctetString)
                            {
                                if (((ASN1OctetString)item).getOctets().length > 32)
                                {
                                    // Outside of range for BitmapSspRange so assume opaque
                                    range.setOpaque((ASN1Sequence)o);
                                    break;
                                }
                            }
                            else
                            {
                                throw new IllegalArgumentException("inner sequence does not contain octet string");
                            }
                        }

                        //
                        // Opaque was not set so assume both.
                        //
                        if (opaque == null)
                        {
                            range.opaque = (ASN1Sequence)o;
                            range.bitmapSspRange = BitmapSspRange.getInstance(o);
                        }

                    }
                    else
                    {
                        range.setOpaque((ASN1Sequence)o);
                    }
                }
                return range;
            }
            catch (IOException e)
            {
                throw new IllegalStateException(e.getMessage(), e);
            }

        } else if (src instanceof byte[]) {
            return getInstance(new ByteArrayInputStream((byte[])src));
        } else if (src instanceof InputStream) {
            return getInstance(new ASN1InputStream((InputStream)src));
        }

        throw new IllegalStateException("Unable to parse SspRange");
    }

    public ASN1Sequence getOpaque()
    {
        return opaque;
    }

    public void setOpaque(ASN1Sequence opaque)
    {
        this.opaque = opaque;
        this.all = null;
        this.bitmapSspRange = null;
    }

    public ASN1Null getAll()
    {
        return all;
    }

    public void setAll()
    {
        this.all = DERNull.INSTANCE;
        this.opaque = null;
        this.bitmapSspRange = null;
    }


    public BitmapSspRange getBitmapSspRange()
    {
        return bitmapSspRange;
    }

    public void setBitmapSspRange(BitmapSspRange bitmapSspRange)
    {
        this.bitmapSspRange = bitmapSspRange;
        this.all = null;
        this.opaque = null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (opaque != null) {
            return opaque;
        }
        if (all != null) {
            return all;
        }

        if (bitmapSspRange != null) {
            return bitmapSspRange.toASN1Primitive();
        }
        throw new IllegalStateException("SspRange has no value");
    }
}
