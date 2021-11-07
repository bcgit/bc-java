package org.bouncycastle.asn1;

import java.io.IOException;

public class BERBitString
    extends ASN1BitString
{
    private static final int DEFAULT_SEGMENT_LIMIT = 1000;

    private final int segmentLimit;
    private final ASN1BitString[] elements;

    /**
     * Convert a vector of bit strings into a single bit string
     */
    static byte[] flattenBitStrings(ASN1BitString[] bitStrings)
    {
        int count = bitStrings.length;
        switch (count)
        {
        case 0:
            // No bits
            return new byte[]{ 0 };
        case 1:
            return bitStrings[0].contents;
        default:
        {
            int last = count - 1, totalLength = 0;
            for (int i = 0; i < last; ++i)
            {
                byte[] elementContents = bitStrings[i].contents;
                if (elementContents[0] != 0)
                {
                    throw new IllegalArgumentException("only the last nested bitstring can have padding");
                }

                totalLength += elementContents.length - 1;
            }

            // Last one can have padding
            byte[] lastElementContents = bitStrings[last].contents;
            byte padBits = lastElementContents[0];
            totalLength += lastElementContents.length;

            byte[] contents = new byte[totalLength];
            contents[0] = padBits;

            int pos = 1;
            for (int i = 0; i < count; ++i)
            {
                byte[] elementContents = bitStrings[i].contents;
                int length = elementContents.length - 1;
                System.arraycopy(elementContents, 1, contents, pos, length);
                pos += length;
            }

//            assert pos == totalLength;
            return contents;
        }
        }
    }
    
    public BERBitString(byte[] data)
    {
        this(data, 0);
    }

    public BERBitString(byte data, int padBits)
    {
        super(data, padBits);
        this.elements = null;
        this.segmentLimit = DEFAULT_SEGMENT_LIMIT;
    }

    public BERBitString(byte[] data, int padBits)
    {
        this(data, padBits, DEFAULT_SEGMENT_LIMIT);
    }

    public BERBitString(byte[] data, int padBits, int segmentLimit)
    {
        super(data, padBits);
        this.elements = null;
        this.segmentLimit = segmentLimit;
    }

    public BERBitString(ASN1Encodable obj) throws IOException
    {
        this(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    public BERBitString(ASN1BitString[] elements)
    {
        this(elements, DEFAULT_SEGMENT_LIMIT);
    }

    public BERBitString(ASN1BitString[] elements, int segmentLimit)
    {
        super(flattenBitStrings(elements), false);
        this.elements = elements;
        this.segmentLimit = segmentLimit;
    }    

    BERBitString(byte[] contents, boolean check)
    {
        super(contents, check);
        this.elements = null;
        this.segmentLimit = DEFAULT_SEGMENT_LIMIT;
    }

    boolean encodeConstructed()
    {
        return null != elements || contents.length > segmentLimit;
    }

    int encodedLength(boolean withTag)
        throws IOException
    {
        if (!encodeConstructed())
        {
            return DLBitString.encodedLength(withTag, contents.length);
        }

        int totalLength = withTag ? 4 : 3;

        if (null != elements)
        {
            for (int i = 0; i < elements.length; ++i)
            {
                totalLength += elements[i].encodedLength(true);
            }
        }
        else if (contents.length < 2)
        {
            // No bits
        }
        else
        {
            int extraSegments = (contents.length - 2) / (segmentLimit - 1);
            totalLength += extraSegments * DLBitString.encodedLength(true, segmentLimit);

            int lastSegmentLength = contents.length - (extraSegments * (segmentLimit - 1));
            totalLength += DLBitString.encodedLength(true, lastSegmentLength);
        }

        return totalLength;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        if (!encodeConstructed())
        {
            DLBitString.encode(out, withTag, contents, 0, contents.length);
            return;
        }

        out.writeIdentifier(withTag, BERTags.CONSTRUCTED | BERTags.BIT_STRING);
        out.write(0x80);

        if (null != elements)
        {
            out.writePrimitives(elements);
        }
        else if (contents.length < 2)
        {
            // No bits
        }
        else
        {
            byte pad = contents[0];
            int length = contents.length;
            int remaining = length - 1;
            int segmentLength = segmentLimit - 1;

            while (remaining > segmentLength)
            {
                DLBitString.encode(out, true, (byte)0, contents, length - remaining, segmentLength);
                remaining -= segmentLength;
            }

            DLBitString.encode(out, true, pad, contents, length - remaining, remaining);
        }

        out.write(0x00);
        out.write(0x00);
    }
}

