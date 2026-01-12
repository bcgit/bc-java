package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Basic class for streaming DER encoding generators.
 */
public abstract class DERGenerator
    extends ASN1Generator
{
    private boolean      _tagged = false;
    private boolean      _isExplicit;
    private int          _tagNo;

    protected DERGenerator(
        OutputStream out)
    {
        super(out);
    }

    /**
     * Create a DER encoding generator for a tagged object.
     *
     * @param out the output stream to encode objects to.
     * @param tagNo the tag number to head the output stream with.
     * @param isExplicit true if the tagging should be explicit, false otherwise.
     */
    public DERGenerator(
        OutputStream out,
        int          tagNo,
        boolean      isExplicit)
    {
        super(out);

        _tagged = true;
        _isExplicit = isExplicit;
        _tagNo = tagNo;
    }

    private void writeLength(
        OutputStream out,
        int          length)
        throws IOException
    {
        if (length > 127)
        {
            int size = 1;
            int val = length;

            while ((val >>>= 8) != 0)
            {
                size++;
            }

            out.write((byte)(size | 0x80));

            for (int i = (size - 1) * 8; i >= 0; i -= 8)
            {
                out.write((byte)(length >> i));
            }
        }
        else
        {
            out.write((byte)length);
        }
    }

    void writeDEREncoded(
        OutputStream out,
        int          tag,
        byte[]       bytes)
        throws IOException
    {
        out.write(tag);
        writeLength(out, bytes.length);
        out.write(bytes);
    }

    void writeDEREncoded(
        int       tag,
        byte[]    bytes)
        throws IOException
    {
        if (!_tagged)
        {
            writeDEREncoded(_out, tag, bytes);
        }
        else if (_isExplicit)
        {
            /*
             * X.690-0207 8.14.2. If implicit tagging [..] was not used [..], the encoding shall be constructed
             * and the contents octets shall be the complete base encoding.
             */
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            writeDEREncoded(bOut, tag, bytes);
            writeDEREncoded(_out, _tagNo | BERTags.CONTEXT_SPECIFIC | BERTags.CONSTRUCTED, bOut.toByteArray());
        }
        else
        {
            /*
             * X.690-0207 8.14.3. If implicit tagging was used [..], then: a) the encoding shall be constructed
             * if the base encoding is constructed, and shall be primitive otherwise; and b) the contents octets
             * shall be [..] the contents octets of the base encoding.
             */
            writeDEREncoded(_out, inheritConstructedFlag(_tagNo | BERTags.CONTEXT_SPECIFIC, tag), bytes);
        }
    }
}
