package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A BIT STRING with DER encoding - the first byte contains the count of padding bits included in the byte array's last byte.
 */
public class DERBitString
    extends ASN1BitString
{
    public static DERBitString convert(ASN1BitString bitString)
    {
        return (DERBitString)bitString.toDERObject();
    }

    public DERBitString(byte[] data)
    {
        this(data, 0);
    }

    public DERBitString(byte data, int padBits)
    {
        super(data, padBits);
    }

    public DERBitString(byte[] data, int padBits)
    {
        super(data, padBits);
    }

    public DERBitString(int value)
    {
        // TODO[asn1] Unify in single allocation of 'contents'
        super(getBytes(value), getPadBits(value));
    }

    public DERBitString(ASN1Encodable obj) throws IOException
    {
        // TODO[asn1] Unify in single allocation of 'contents'
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    DERBitString(byte[] contents, boolean check)
    {
        super(contents, check);
    }

    boolean encodeConstructed()
    {
        return false;
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        int padBits = contents[0] & 0xFF;
        int length = contents.length;
        int last = length - 1;

        byte lastOctet = contents[last];
        byte lastOctetDER = (byte)(contents[last] & (0xFF << padBits));

        if (lastOctet == lastOctetDER)
        {
            out.writeEncodingDL(withTag, BERTags.BIT_STRING, contents);
        }
        else
        {
            out.writeEncodingDL(withTag, BERTags.BIT_STRING, contents, 0, last, lastOctetDER);
        }
    }

    ASN1Primitive toDERObject()
    {
        return this;
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }

    static DERBitString fromOctetString(ASN1OctetString octetString)
    {
        return new DERBitString(octetString.getOctets(), true);
    }
}
