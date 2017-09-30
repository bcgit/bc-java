package com.github.gv2011.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Base class for generators for indefinite-length structures.
 */
public class BERGenerator
    extends ASN1Generator
{
    private boolean      _tagged = false;
    private boolean      _isExplicit;
    private int          _tagNo;

    protected BERGenerator(
        final OutputStream out)
    {
        super(out);
    }

    protected BERGenerator(
        final OutputStream out,
        final int tagNo,
        final boolean isExplicit)
    {
        super(out);

        _tagged = true;
        _isExplicit = isExplicit;
        _tagNo = tagNo;
    }

    @Override
    public OutputStream getRawOutputStream()
    {
        return _out;
    }

    private void writeHdr(
        final int tag)
        throws IOException
    {
        _out.write(tag);
        _out.write(0x80);
    }

    protected void writeBERHeader(
        final int tag)
        throws IOException
    {
        if (_tagged)
        {
            final int tagNum = _tagNo | BERTags.TAGGED;

            if (_isExplicit)
            {
                writeHdr(tagNum | BERTags.CONSTRUCTED);
                writeHdr(tag);
            }
            else
            {
                if ((tag & BERTags.CONSTRUCTED) != 0)
                {
                    writeHdr(tagNum | BERTags.CONSTRUCTED);
                }
                else
                {
                    writeHdr(tagNum);
                }
            }
        }
        else
        {
            writeHdr(tag);
        }
    }

    protected void writeBEREnd()
        throws IOException
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
