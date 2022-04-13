package org.bouncycastle.asn1.cmp;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
 *          -- text encoded as UTF-8 String [RFC3629] (note: each
 *          -- UTF8String MAY include an [RFC3066] language tag
 *          -- to indicate the language of the contained text
 *          -- see [RFC2482] for details)
 */
public class PKIFreeText
    extends ASN1Object
{
    ASN1Sequence strings;

    private PKIFreeText(
        ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements())
        {
            if (!(e.nextElement() instanceof ASN1UTF8String))
            {
                throw new IllegalArgumentException("attempt to insert non UTF8 STRING into PKIFreeText");
            }
        }

        strings = seq;
    }

    public PKIFreeText(
        ASN1UTF8String p)
    {
        strings = new DERSequence(p);
    }

    public PKIFreeText(
        String p)
    {
        this(new DERUTF8String(p));
    }

    public PKIFreeText(
        ASN1UTF8String[] strs)
    {
        strings = new DERSequence(strs);
    }

    public PKIFreeText(
        String[] strs)
    {
        ASN1EncodableVector v = new ASN1EncodableVector(strs.length);
        for (int i = 0; i < strs.length; i++)
        {
            v.add(new DERUTF8String(strs[i]));
        }
        strings = new DERSequence(v);
    }

    public static PKIFreeText getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static PKIFreeText getInstance(
        Object obj)
    {
        if (obj instanceof PKIFreeText)
        {
            return (PKIFreeText)obj;
        }
        else if (obj != null)
        {
            return new PKIFreeText(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Return the number of string elements present.
     *
     * @return number of elements present.
     */
    public int size()
    {
        return strings.size();
    }

    /**
     * Return the UTF8STRING at index i.
     *
     * @param i index of the string of interest
     * @return the string at index i.
     * @deprecated Use {@link #getStringAtUTF8(int)} instead.
     */
    public DERUTF8String getStringAt(int i)
    {
        ASN1UTF8String stringAt = getStringAtUTF8(i);
        return null == stringAt || stringAt instanceof DERUTF8String
            ? (DERUTF8String)stringAt
            : new DERUTF8String(stringAt.getString());
    }

    /**
     * Return the UTF8STRING at index i.
     *
     * @param i index of the string of interest
     * @return the string at index i.
     */
    public ASN1UTF8String getStringAtUTF8(int i)
    {
        return (ASN1UTF8String)strings.getObjectAt(i);
    }

    /**
     * <pre>
     * PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return strings;
    }
}
