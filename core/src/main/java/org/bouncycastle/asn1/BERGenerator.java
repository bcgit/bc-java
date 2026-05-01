package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Base class for generators for indefinite-length structures.
 */
public abstract class BERGenerator
    extends ASN1Generator
{
    private boolean _tagged = false;
    private boolean _isExplicit;
    private int _tagNo;

    protected BERGenerator(OutputStream out)
    {
        super(out);
    }

    protected BERGenerator(OutputStream out, int tagNo, boolean isExplicit)
    {
        super(out);

        // TODO Check proper handling of implicit tagging
        _tagged = true;
        _isExplicit = isExplicit;
        _tagNo = tagNo;
    }

    public OutputStream getRawOutputStream()
    {
        return _out;
    }

    private void writeHdr(int tag) throws IOException
    {
        _out.write(tag);
        _out.write(0x80);
    }

    protected void writeBERHeader(int tag) throws IOException
    {
        if (!_tagged)
        {
            writeHdr(tag);
        }
        else if (_isExplicit)
        {
            /*
             * X.690-0207 8.14.2. If implicit tagging [..] was not used [..], the encoding shall be constructed
             * and the contents octets shall be the complete base encoding.
             */
            writeHdr(_tagNo | BERTags.CONTEXT_SPECIFIC | BERTags.CONSTRUCTED);
            writeHdr(tag);
        }
        else
        {
            /*
             * X.690-0207 8.14.3. If implicit tagging was used [..], then: a) the encoding shall be constructed
             * if the base encoding is constructed, and shall be primitive otherwise; and b) the contents octets
             * shall be [..] the contents octets of the base encoding.
             */
            writeHdr(inheritConstructedFlag(_tagNo | BERTags.CONTEXT_SPECIFIC, tag));
        }
    }

    protected void writeBEREnd() throws IOException
    {
        _out.write(0x00);
        _out.write(0x00);

        if (_tagged && _isExplicit)  // write extra end for tag header
        {
            _out.write(0x00);
            _out.write(0x00);
        }
    }
}
