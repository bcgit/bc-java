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
        if (_tagged)
        {
            int tagNum = _tagNo | BERTags.TAGGED;

            if (_isExplicit)
            {
                int newTag = _tagNo | BERTags.CONSTRUCTED | BERTags.TAGGED;

                ByteArrayOutputStream bOut = new ByteArrayOutputStream();

                writeDEREncoded(bOut, tag, bytes);

                writeDEREncoded(_out, newTag, bOut.toByteArray());
            }
            else
            {
                if ((tag & BERTags.CONSTRUCTED) != 0)
                {
                    writeDEREncoded(_out, tagNum | BERTags.CONSTRUCTED, bytes);
                }
                else
                {
                    writeDEREncoded(_out, tagNum, bytes);
                }
            }
        }
        else
        {
            writeDEREncoded(_out, tag, bytes);
        }
    }
}
