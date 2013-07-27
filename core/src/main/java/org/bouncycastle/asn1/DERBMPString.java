package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * DER BMPString object encodes BMP (<i>Basic Multilingual Plane</i>) subset
 * (aka UCS-2) of UNICODE (ISO 10646) characters in codepoints 0 to 65535.
 * <p>
 * At ISO-10646:2011 the term "BMP" has been withdrawn, and replaced by
 * term "UCS-2".
 * <hr>
 * <h2>X.690</h2>
 * <h3>8: Basic encoding rules</h3>
 * <h4>8.21 Encoding for values of the restricted character string types </h4>
 * <b>8.21.1</b> The data value consists of a string of characters from
 * the character set specified in the ASN.1 type definition
 * <p>
 * <b>8.21.2</b> Each data value shall be encoded independently
 * of other data values of the same type. 
 * <p>
 * <b>8.21.3</b> Each character string type shall be encoded
 * as if it had been declared: 
 * <blockquote>
 * <b>[UNIVERSAL x] IMPLICIT OCTET STRING </b>
 * </blockquote>
 * where x is the number of the universal class tag
 * assigned to the character string type in ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * The value of the octet string is specified in 8.21.4 and 8.21.5.
 * <p>
 * <b>8.21.4</b> Where a character string type is specified
 * in ITU-T Rec. X.680 | ISO/IEC 8824-1 by direct reference to
 * an enumerating table (NumericString and PrintableString),
 * the value of the octet string shall be that specified in 
 * 8.21.5 for a VisibleString type with the same character string value. 
 * <p>
 * <b>8.21.5</b> For restricted character strings apart from
 * UniversalString and BMPString, the octet string shall contain 
 * the octets specified in ISO/IEC 2022 for encodings in
 * an 8-bit environment, using the escape sequence and character
 * codings registered in accordance with ISO 2375.
 * <p>
 * <b>8.21.5.1</b> An escape sequence shall not be used
 * unless it is one of those specified by one of
 * the registration numbers used to define the character
 * string type in ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * <p>
 * <b>8.21.5.2</b> At the start of each string, certain
 * registration numbers shall be assumed to be designated
 * as G0 and/or C0 and/or C1, and invoked (using
 * the terminology of ISO/IEC 2022). These are specified
 * for each type in Table 3, together with the assumed escape sequence they imply.
 * <p>
 *
 * [ESCAPE CODE TABLE 3]
 * <p>
 * <b>8.21.5.3</b> Certain character string types shall not
 * contain explicit escape sequences in their encodings;
 * in all other cases, any escape sequence allowed by 8.21.5.1
 * can appear at any time, including at the start of the encoding.
 * Table 3 lists the types for which explicit escape sequences are allowed.
 * <p>
 * <b>8.21.5.4</b> Announcers shall not be used unless explicitly permitted
 * by the user of ASN.1.
 * <blockquote>
 * NOTE &mdash; The choice of ASN.1 type provides a limited form of
 * announcer functionality. Specific application protocols may choose 
 * to carry announcers in other protocol elements, or to specify
 * in detail the manner of use of announcers. 
 * </blockquote>
 * <b>8.21.8</b> For the BMPString type, the octet string
 * shall contain the octets specified in ISO/IEC 10646-1,
 * using the 2-octet BMP form (see 13.1 of ISO/IEC 10646-1).
 * Signatures shall not be used. Control functions may be used provided 
 * they satisfy the restrictions imposed by 8.21.9.
 * <p>
 * <b>8.21.9</b> The C0 and C1 control functions of ISO/IEC 6429
 * may be used with the following exceptions.
 * <blockquote>
 * NOTE 1 &mdash; The effect of this subclause is to allow
 * the useful control functions such as LF, CR, TAB, etc.,
 * while forbidding the use of escapes to other character sets.
 * <p>
 * NOTE 2 &mdash; The C0 and C1 control functions are each
 * encoded in two octets for BMPString and four for UniversalString.
 * <ol type="a">
 * <li>Announcer escape sequences defined in ISO/IEC 2022 shall not be used.
 * <blockquote>
 * NOTE 3 &mdash; The assumed character coding environment is ISO/IEC 10646-1.
 * </blockquote></li>
 * <li>Designating or identifying escape sequences defined
 * in ISO/IEC 2022 shall not be used, including the identifying 
 * escape sequences permitted by ISO/IEC 10646-1, 17.2 and 17.4.
 * <blockquote>
 * NOTE 4 &mdash; ASN.1 allows the use of the PermittedAlphabet
 * subtype notation to select the set of allowed characters.
 * PermittedAlphabet is also used to select the level of
 * implementation of ISO/IEC 10646-1. BMPString is always used
 * for the two-octet form and UniversalString for the four-octet form.
 * </blockquote></li>
 * <li>Invoking escape sequence or control sequences of
 * ISO/IEC 2022 shall not be used, such as SHIFT IN (SI),
 * SHIFT OUT (SO), or LOCKING SHIFT FOR G3 (SS3) </li>
 * <li>The coding shall conform to ISO/IEC 10646-1 and
 * remain in that code set. </li>
 * <li>Control sequences for identifying subsets of graphic
 * characters according to ISO/IEC 10646-1, 16.3, shall not be used.
 * <blockquote>
 * NOTE 5 &mdash; ASN.1 applications use subtyping to indicate
 * subsets of the graphic characters of ISO/IEC 10646-1 
 * and to select the ISO/IEC 10646-1 cells that correspond
 * to the control characters of ISO/IEC 6429.
 * </blockquote></li>
 * <li>The escape sequences of ISO/IEC 10646-1, 16.5,
 * shall not be used to switch to ISO/IEC 2022 codes.</li>
 * </ol>
 */

public class DERBMPString
    extends ASN1Primitive
    implements ASN1String
{
    private char[]  string;

    /**
     * Return a BMP String from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DERBMPString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERBMPString)
        {
            return (DERBMPString)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (DERBMPString)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a BMP String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *              be converted.
     */
    public static DERBMPString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERBMPString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERBMPString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * Basic constructor - byte encoded string.
     */
    DERBMPString(
        byte[]   string)
    {
        char[]  cs = new char[string.length / 2];

        for (int i = 0; i != cs.length; i++)
        {
            cs[i] = (char)((string[2 * i] << 8) | (string[2 * i + 1] & 0xff));
        }

        this.string = cs;
    }

    DERBMPString(char[] string)
    {
        this.string = string;
    }

    /**
     * Basic constructor
     */
    public DERBMPString(
        String   string)
    {
        this.string = string.toCharArray();
    }

    public String getString()
    {
        return new String(string);
    }

    @Override
    public String toString()
    {
        return getString();
    }

    @Override
    public int hashCode()
    {
        return Arrays.hashCode(string);
    }

    protected boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof DERBMPString))
        {
            return false;
        }

        DERBMPString  s = (DERBMPString)o;

        return Arrays.areEqual(string, s.string);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length * 2) + (string.length * 2);
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.write(BERTags.BMP_STRING);
        out.writeLength(string.length * 2);

        for (int i = 0; i != string.length; i++)
        {
            char c = string[i];

            out.write((byte)(c >> 8));
            out.write((byte)c);
        }
    }
}
