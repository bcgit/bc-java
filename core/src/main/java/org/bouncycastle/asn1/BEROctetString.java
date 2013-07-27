package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Vector;

/**
 * ASN.1 OctetStrings, with indefinite length rules, and <i>constructed form</i> support.
 * <p>
 * The Basic Encoding Rules (BER) format allows encoding using so called "<i>constructed form</i>",
 * which DER and CER formats forbid allowing only "primitive form".
 * <p>
 * This class produces <b>always</b> the constructed form with underlying segments
 * in an indefinite length array.  If the input wasn't the same, then this output
 * is not faithful reproduction.
 * <p>
 *
 *<hr>
 * <h2>X.690 chapter 8: Basic encoding rules</h2>
 * <h3>8.7 Encoding of an octetstring value</h3>
 * <p>
 * <b>8.7.1</b> The encoding of an octetstring value shall be
 * either primitive or constructed at the option of the sender.
 * <blockquote>
 * NOTE &mdash; Where it is necessary to transfer part of an octet string
 * before the entire octetstring is available, the constructed encoding is used.
 * </blockquote>
 * <p>
 * <b>8.7.2</b> The primitive encoding contains zero, one or more
 * contents octets equal in value to the octets in the data value, 
 * in the order they appear in the data value, and with the most
 * significant bit of an octet of the data value aligned with the 
 * most significant bit of an octet of the contents octets.
 * <p>
 * <b>8.7.3</b> The contents octets for the constructed encoding
 * shall consist of zero, one, or more encodings. 
 * <blockquote>
 * NOTE &mdash; Each such encoding includes identifier, length, and
 * contents octets, and may include end-of-contents octets if
 * it is constructed.
 * </blockquote>
 * <p>
 * <b>8.7.3.1</b> To encode an octetstring value in this way,
 * it is segmented. Each segment shall consist of a series of 
 * consecutive octets of the value.
 * There shall be no significance placed on the segment boundaries.
 * <blockquote>
 * NOTE &mdash; A segment may be of size zero, i.e. contain no octets.
 * </blockquote>
 * <p>
 * <b>8.7.3.2</b> Each encoding in the contents octets shall represent
 * a segment of the overall octetstring, the encoding arising 
 * from a recursive application of this subclause.
 * In this recursive application, each segment is treated as if it were
 * a octetstring value. The encodings of the segments shall appear in
 * the contents octets in the order in which their octets appear
 * in the overall value.
 * <blockquote>
 * NOTE 1 &mdash; As a consequence of this recursion, each encoding in
 * the contents octets may itself be primitive or constructed. 
 * However, such encodings will usually be primitive.
 * <p>
 * NOTE 2 &mdash; In particular, the tags in the contents octets are
 * always universal class, number 4.
 * </blockquote>
 */

public class BEROctetString
    extends ASN1OctetString
{
    private static final int MAX_LENGTH = 1000; // Limit of CER encoding requiring use of constructed form

    private ASN1OctetString[] octs;

    /**
     * Convert a vector of octet strings into a single byte string
     */
    static private byte[] toBytes(
        ASN1OctetString[]  octs)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        for (int i = 0; i != octs.length; i++)
        {
            try
            {
                DEROctetString o = (DEROctetString)octs[i];

                bOut.write(o.getOctets());
            }
            catch (ClassCastException e)
            {
                throw new IllegalArgumentException(octs[i].getClass().getName() + " found in input should only contain DEROctetString");
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("exception converting octets " + e.toString());
            }
        }

        return bOut.toByteArray();
    }

    /**
     * Create an OCTET-STRING object from a byte[]
     *
     * @param string the octets making up the octet string.
     */
    public BEROctetString(
        byte[] string)
    {
        super(string);
    }

    /**
     * Multiple {@link ASN1OctetString} data blocks are input,
     * the result is <i>constructed form</i>.
     *
     * @param octs
     */
    public BEROctetString(
        ASN1OctetString[] octs)
    {
        super(toBytes(octs));

        this.octs = octs;
    }

    /**
     * Get concatenated byte array out from input array of byte arrays.
     */
    @Override
    public byte[] getOctets()
    {
        return string;
    }

    /**
     * Return the DER octets that make up this byte[] string.
     */
    public Enumeration getObjects()
    {
        if (octs == null)
        {
            return generateOcts().elements();
        }

        return new Enumeration()
        {
            int counter = 0;

            public boolean hasMoreElements()
            {
                return counter < octs.length;
            }

            public Object nextElement()
            {
                return octs[counter++];
            }
        };
    }

    private Vector generateOcts()
    { 
        Vector vec = new Vector();
        for (int i = 0; i < string.length; i += MAX_LENGTH) 
        { 
            int end; 

            if (i + MAX_LENGTH > string.length) 
            { 
                end = string.length; 
            } 
            else 
            { 
                end = i + MAX_LENGTH; 
            } 

            byte[] nStr = new byte[end - i]; 

            System.arraycopy(string, i, nStr, 0, nStr.length);

            vec.addElement(new DEROctetString(nStr));
         } 
        
         return vec; 
    }

    /**
     * This form is always a constructed one.
     */
    boolean isConstructed()
    {
        return true;
    }

    int encodedLength()
        throws IOException
    {
        int length = 0;
        for (Enumeration e = getObjects(); e.hasMoreElements();)
        {
            length += ((ASN1Encodable)e.nextElement()).toASN1Primitive().encodedLength();
        }

        return 2 + length + 2;
    }

    /**
     * Encode indefinite-form CONSTRUCTED OCTET-STRING.
     */
    @Override
    public void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.write(BERTags.CONSTRUCTED | BERTags.OCTET_STRING);

        out.write(0x80);

        //
        // write out the octet array
        //
        for (Enumeration e = getObjects(); e.hasMoreElements();)
        {
            out.writeObject((ASN1Encodable)e.nextElement());
        }

        out.write(0x00);
        out.write(0x00);
    }

    /**
     * Construct BEROctetString from a SEQUENCE of OCTET-STRINGs.
     * <p>
     * Every element of the sequence must be an {@link ASN1OctetString}.
     * In particular if a constructed form of BEROctetString is given as
     * an array element, it is automatically concatenated into
     * DER-compatible form first.
     * 
     */
    static BEROctetString fromSequence(ASN1Sequence seq)
    {
        ASN1OctetString[]     v = new ASN1OctetString[seq.size()];
        Enumeration e = seq.getObjects();
        int                   index = 0;

        while (e.hasMoreElements())
        {
            v[index++] = (ASN1OctetString)e.nextElement();
        }

        return new BEROctetString(v);
    }
}
