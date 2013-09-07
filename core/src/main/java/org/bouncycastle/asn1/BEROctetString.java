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
 *<hr>
 * See {@link ASN1OctetString} for X.690 encoding rules of OCTET-STRING objects.
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
    // @Override
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
    // @Override
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
