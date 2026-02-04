package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * Carrier class for a DER encoding OCTET STRING
 */
public class DEROctetString
    extends ASN1OctetString
{
    public static final DEROctetString EMPTY = new DEROctetString(EMPTY_OCTETS);

    public static DEROctetString fromContents(byte[] contents)
    {
        if (contents == null)
        {
            throw new NullPointerException("'contents' cannot be null");
        }

        return internalFromContents(contents);
    }

    public static DEROctetString fromContentsOptional(byte[] contents)
    {
        return contents == null ? null : internalFromContents(contents);
    }

    public static DEROctetString withContents(byte[] contents)
    {
        if (contents == null)
        {
            throw new NullPointerException("'contents' cannot be null");
        }

        return internalWithContents(contents);
    }

    public static DEROctetString withContentsOptional(byte[] contents)
    {
        return contents == null ? null : internalWithContents(contents);
    }

    static DEROctetString internalFromContents(byte[] contents)
    {
        return contents.length < 1 ? EMPTY : new DEROctetString(Arrays.clone(contents));
    }

    static DEROctetString internalWithContents(byte[] contents)
    {
        return contents.length < 1 ? EMPTY : new DEROctetString(contents);
    }

    /**
     * Base constructor.
     *
     * @param string the octets making up the octet string.
     */
    public DEROctetString(
        byte[]  string)
    {
        super(string);
    }

    /**
     * Constructor from the encoding of an ASN.1 object.
     *
     * @param obj the object to be encoded.
     */
    public DEROctetString(
        ASN1Encodable obj)
        throws IOException
    {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    boolean encodeConstructed()
    {
        return false;
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, string.length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.OCTET_STRING, string);
    }

    ASN1Primitive toDERObject()
    {
        return this;
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }

    static void encode(ASN1OutputStream out, boolean withTag, byte[] buf, int off, int len) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.OCTET_STRING, buf, off, len);
    }

    static int encodedLength(boolean withTag, int contentsLength)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contentsLength);
    }
}
