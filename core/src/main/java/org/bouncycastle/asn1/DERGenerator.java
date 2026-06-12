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

    void writeDEREncoded(OutputStream out, int tag, byte[] bytes) throws IOException
    {
        out.write(tag);
        ASN1OutputStream.writeDL(out, bytes.length);
        out.write(bytes);
    }

    private void writeDEREncoded(OutputStream out, int flags, int tagNo, byte[] bytes) throws IOException
    {
        ASN1OutputStream.writeIdentifier(out, flags, tagNo);
        ASN1OutputStream.writeDL(out, bytes.length);
        out.write(bytes);
    }

    void writeDEREncoded(int tag, byte[] bytes) throws IOException
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
            writeDEREncoded(_out, BERTags.CONTEXT_SPECIFIC | BERTags.CONSTRUCTED, _tagNo, bOut.toByteArray());
        }
        else
        {
            /*
             * X.690-0207 8.14.3. If implicit tagging was used [..], then: a) the encoding shall be constructed
             * if the base encoding is constructed, and shall be primitive otherwise; and b) the contents octets
             * shall be [..] the contents octets of the base encoding.
             */
            writeDEREncoded(_out, inheritConstructedFlag(BERTags.CONTEXT_SPECIFIC, tag), _tagNo, bytes);
        }
    }
}
