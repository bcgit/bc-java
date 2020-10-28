package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.NoSuchElementException;

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
    private static final int DEFAULT_CHUNK_SIZE = 1000;

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
                bOut.write(octs[i].getOctets());
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
        this(string, DEFAULT_CHUNK_SIZE);
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
        this(octs, DEFAULT_CHUNK_SIZE);
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
     * Return the OCTET STRINGs that make up this string.
     *
     * @return an Enumeration of the component OCTET STRINGs.
     */
    public Enumeration getObjects()
    {
        if (octs == null)
        {
            return new Enumeration()
            {
                int pos = 0;

                public boolean hasMoreElements()
                {
                    return pos < string.length;
                }

                public Object nextElement()
                {
                    if (pos < string.length)
                    {
                        int length = Math.min(string.length - pos, chunkSize);
                        byte[] chunk = new byte[length];
                        System.arraycopy(string, pos, chunk, 0, length);
                        pos += length;
                        return new DEROctetString(chunk);
                    }
                    throw new NoSuchElementException();
                }
            };
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
                if (counter < octs.length)
                {
                    return octs[counter++];
                }
                throw new NoSuchElementException();
            }
        };
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

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodedIndef(withTag, BERTags.CONSTRUCTED | BERTags.OCTET_STRING,  getObjects());
    }

    static BEROctetString fromSequence(ASN1Sequence seq)
    {
        int count = seq.size();
        ASN1OctetString[] v = new ASN1OctetString[count];
        for (int i = 0; i < count; ++i)
        {
            v[i] = ASN1OctetString.getInstance(seq.getObjectAt(i));
        }
        return new BEROctetString(v);
    }
}
