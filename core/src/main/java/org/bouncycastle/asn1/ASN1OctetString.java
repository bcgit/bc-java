package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Abstract base of ASN.1 OCTET-STRING data type
 * <p>
 * This supports BER, DER, and CER forms of the data.
 * <p>
 * DER form is always canonic single OCTET STRING, while
 * BER and CER support constructed forms.
 * <p>
 * <hr>
 * <p>
 * <h2>X.690</h2>
 * <p>
 * <h3>8: Basic encoding rules</h3>
 * <h4>8.7 Encoding of an octetstring value</h4>
 * <b>8.7.1</b> The encoding of an octetstring value shall be
 * either primitive or constructed at the option of the sender. 
 * <blockquote>
 * NOTE &mdash; Where it is necessary to transfer part of an octet string
 * before the entire octetstring is available, the constructed encoding 
 * is used.
 * </blockquote>
 * <p>
 * <b>8.7.2</b> The primitive encoding contains zero,
 * one or more contents octets equal in value to the octets
 * in the data value, in the order they appear in the data value,
 * and with the most significant bit of an octet of the data value
 * aligned with the most significant bit of an octet of the contents octets. 
 * <p>
 * <b>8.7.3</b> The contents octets for the constructed encoding shall consist
 * of zero, one, or more encodings.
 * <blockquote>
 * NOTE &mdash; Each such encoding includes identifier, length, and contents octets,
 * and may include end-of-contents octets if it is constructed.
 * </blockquote>
 * <p>
 * <b>8.7.3.1</b> To encode an octetstring value in this way,
 * it is segmented. Each segment shall consist of a series of 
 * consecutive octets of the value. There shall be no significance
 * placed on the segment boundaries.
 * <blockquote>
 * NOTE &mdash; A segment may be of size zero, i.e. contain no octets.
 * </blockquote>
 * <b>8.7.3.2</b> Each encoding in the contents octets shall represent
 * a segment of the overall octetstring, the encoding arising from
 * a recursive application of this subclause.
 * In this recursive application, each segment is treated as if it were
 * a octetstring value. The encodings of the segments shall appear in the contents
 * octets in the order in which their octets appear in the overall value.
 * <blockquote>
 * NOTE 1 &mdash; As a consequence of this recursion,
 * each encoding in the contents octets may itself
 * be primitive or constructed.
 * However, such encodings will usually be primitive.
 * <p>
 * NOTE 2 &mdash; In particular, the tags in the contents octets are always universal class, number 4.
 * </blockquote>
 */

public abstract class ASN1OctetString
    extends ASN1Primitive
    implements ASN1OctetStringParser
{
    byte[]  string;

    /**
     * Return an Octet String from a tagged object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> If 'explicit == true', see {@link #getInstance(Object) getInstance(Object)}.
     * <li> {@link ASN1OctetString} object
     * <li> {@link ASN1Sequence#getInstance(Object) ASN1Sequence} input formats where
     * <pre>
     *   SEQUENCE {
     *       o1 OCTET STRING,
     *       o2 OCTET STRING,
     *     ...
     *   }</pre>
     * structure contained segments of a CONSTRUCTED form of OCTET STRING. 
     * See {@link BEROctetString#fromSequence(ASN1Sequence) BEROctetString}.
     * </ul>
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *              be converted.
     */
    public static ASN1OctetString getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof ASN1OctetString)
        {
            return getInstance(o);
        }
        else
        {
            return BEROctetString.fromSequence(ASN1Sequence.getInstance(o));
        }
    }
    
    /**
     * Return an Octet String from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link ASN1OctetString} object
     * <li> A byte[] with DER form of ASN1OctetString..
     * <li> {@link ASN1Encodable} object with ASN1OctetString in it.
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1OctetString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof ASN1OctetString)
        {
            return (ASN1OctetString)obj;
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return ASN1OctetString.getInstance(ASN1Primitive.fromByteArray((byte[])obj));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct OCTET STRING from byte[]: " + e.getMessage());
            }
        }
        else if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();

            if (primitive instanceof ASN1OctetString)
            {
                return (ASN1OctetString)primitive;
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * @param string the octets making up the octet string.
     */
    public ASN1OctetString(
        byte[]  string)
    {
        if (string == null)
        {
            throw new NullPointerException("string cannot be null");
        }
        this.string = string;
    }

    /**
     * Byte datastream of OCTET-STRING content.
     */
    public InputStream getOctetStream()
    {
        return new ByteArrayInputStream(string);
    }

    public ASN1OctetStringParser parser()
    {
        return this;
    }

    /**
     * Get context octets from this OCTET-STRING.
     */
    public byte[] getOctets()
    {
        return string;
    }

    /**
     * Get hashCode() for this OCTET-STRING content.
     */
    @Override
    public int hashCode()
    {
        return Arrays.hashCode(this.getOctets());
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof ASN1OctetString))
        {
            return false;
        }

        ASN1OctetString  other = (ASN1OctetString)o;

        return Arrays.areEqual(string, other.string);
    }

    public ASN1Primitive getLoadedObject()
    {
        return this.toASN1Primitive();
    }

    ASN1Primitive toDERObject()
    {
        return new DEROctetString(string);
    }

    ASN1Primitive toDLObject()
    {
        return new DEROctetString(string);
    }

    abstract void encode(ASN1OutputStream out)
        throws IOException;

    @Override
    public String toString()
    {
      return "#"+new String(Hex.encode(string));
    }
}
