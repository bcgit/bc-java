package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * A DER encoding version of an application specific object.
 */
public class DLApplicationSpecific
    extends ASN1ApplicationSpecific
{
    DLApplicationSpecific(
        boolean isConstructed,
        int     tag,
        byte[]  octets)
    {
        super(isConstructed, tag, octets);
    }

    /**
     * Create an application specific object from the passed in data. This will assume
     * the data does not represent a constructed object.
     *
     * @param tag the tag number for this object.
     * @param octets the encoding of the object's body.
     */
    public DLApplicationSpecific(
        int    tag,
        byte[] octets)
    {
        this(false, tag, octets);
    }

    /**
     * Create an application specific object with a tagging of explicit/constructed.
     *
     * @param tag the tag number for this object.
     * @param object the object to be contained.
     */
    public DLApplicationSpecific(
        int           tag,
        ASN1Encodable object)
        throws IOException
    {
        this(true, tag, object);
    }

    /**
     * Create an application specific object with the tagging style given by the value of constructed.
     *
     * @param constructed true if the object is constructed.
     * @param tag the tag number for this object.
     * @param object the object to be contained.
     */
    public DLApplicationSpecific(
        boolean      constructed,
        int          tag,
        ASN1Encodable object)
        throws IOException
    {
        super(constructed || object.toASN1Primitive().isConstructed(), tag, getEncoding(constructed, object));
    }

    private static byte[] getEncoding(boolean explicit, ASN1Encodable object)
        throws IOException
    {
        byte[] data = object.toASN1Primitive().getEncoded(ASN1Encoding.DL);

        if (explicit)
        {
            return data;
        }
        else
        {
            int lenBytes = getLengthOfHeader(data);
            byte[] tmp = new byte[data.length - lenBytes];
            System.arraycopy(data, lenBytes, tmp, 0, tmp.length);
            return tmp;
        }
    }

    /**
     * Create an application specific object which is marked as constructed
     *
     * @param tagNo the tag number for this object.
     * @param vec the objects making up the application specific object.
     */
    public DLApplicationSpecific(int tagNo, ASN1EncodableVector vec)
    {
        super(true, tagNo, getEncodedVector(vec));
    }

    private static byte[] getEncodedVector(ASN1EncodableVector vec)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        for (int i = 0; i != vec.size(); i++)
        {
            try
            {
                bOut.write(((ASN1Object)vec.get(i)).getEncoded(ASN1Encoding.DL));
            }
            catch (IOException e)
            {
                throw new ASN1ParsingException("malformed object: " + e, e);
            }
        }
        return bOut.toByteArray();
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Primitive#encode(org.bouncycastle.asn1.DEROutputStream)
     */
    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        int flags = BERTags.APPLICATION;
        if (isConstructed)
        {
            flags |= BERTags.CONSTRUCTED;
        }

        out.writeEncoded(withTag, flags, tag, octets);
    }
}
