package com.github.gv2011.asn1;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


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
