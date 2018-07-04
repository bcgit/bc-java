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
 * </p><p>
 * This class <b>always</b> produces the constructed form with underlying segments
 * in an indefinite length array.  If the input wasn't the same, then this output
 * is not faithful reproduction.
 * </p>
 * <p>
 * See {@link ASN1OctetString} for X.690 encoding rules of OCTET-STRING objects.
 * </p>
 */
public class BEROctetString
    extends ASN1OctetString
{
    private static final int DEFAULT_LENGTH = 1000;

    private final int chunkSize;
    private final ASN1OctetString[] octs;

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
     * @param string the octets making up the octet string.
     */
    public BEROctetString(
        byte[] string)
    {
        this(string, DEFAULT_LENGTH);
    }

    /**
     * Multiple {@link ASN1OctetString} data blocks are input,
     * the result is <i>constructed form</i>.
     *
     * @param octs an array of OCTET STRING to construct the BER OCTET STRING from.
     */
    public BEROctetString(
        ASN1OctetString[] octs)
    {
        this(octs, DEFAULT_LENGTH);
    }

    /**
     * Create an OCTET-STRING object from a byte[]
     * @param string the octets making up the octet string.
     * @param chunkSize the number of octets stored in each DER encoded component OCTET STRING.
     */
    public BEROctetString(
        byte[] string,
        int    chunkSize)
    {
        this(string, null, chunkSize);
    }

    /**
     * Multiple {@link ASN1OctetString} data blocks are input,
     * the result is <i>constructed form</i>.
     *
     * @param octs an array of OCTET STRING to construct the BER OCTET STRING from.
     * @param chunkSize the number of octets stored in each DER encoded component OCTET STRING.
     */
    public BEROctetString(
        ASN1OctetString[] octs,
        int chunkSize)
    {
        this(toBytes(octs), octs, chunkSize);
    }

    private BEROctetString(byte[] string, ASN1OctetString[] octs, int chunkSize)
    {
        super(string);
        this.octs = octs;
        this.chunkSize = chunkSize;
    }

    /**
     * Return a concatenated byte array of all the octets making up the constructed OCTET STRING
     * @return the full OCTET STRING.
     */
    public byte[] getOctets()
    {
        return string;
    }

    /**
     * Return the OCTET STRINGs that make up this string.
     *
     * @return an Enumeration of the component OCTET STRINGs.
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
        for (int i = 0; i < string.length; i += chunkSize)
        { 
            int end; 

            if (i + chunkSize > string.length)
            { 
                end = string.length; 
            } 
            else 
            { 
                end = i + chunkSize;
            } 

            byte[] nStr = new byte[end - i]; 

            System.arraycopy(string, i, nStr, 0, nStr.length);

            vec.addElement(new DEROctetString(nStr));
         } 
        
         return vec; 
    }

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
