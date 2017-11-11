package com.github.gv2011.asn1.util.encoders;

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



/**
 * A buffering class to allow translation from one format to another to
 * be done in discrete chunks.
 */
public class BufferedEncoder
{
    protected byte[]        buf;
    protected int           bufOff;

    protected Translator    translator;

    /**
     * @param translator the translator to use.
     * @param bufSize amount of input to buffer for each chunk.
     */
    public BufferedEncoder(
        Translator  translator,
        int         bufSize)
    {
        this.translator = translator;

        if ((bufSize % translator.getEncodedBlockSize()) != 0)
        {
            throw new IllegalArgumentException("buffer size not multiple of input block size");
        }

        buf = new byte[bufSize];
        bufOff = 0;
    }

    public int processByte(
        byte        in,
        byte[]      out,
        int         outOff)
    {
        int         resultLen = 0;

        buf[bufOff++] = in;

        if (bufOff == buf.length)
        {
            resultLen = translator.encode(buf, 0, buf.length, out, outOff);
            bufOff = 0;
        }

        return resultLen;
    }

    public int processBytes(
        byte[]      in,
        int         inOff,
        int         len,
        byte[]      out,
        int         outOff)
    {
        if (len < 0)
        {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }

        int resultLen = 0;
        int gapLen = buf.length - bufOff;

        if (len > gapLen)
        {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);

            resultLen += translator.encode(buf, 0, buf.length, out, outOff);

            bufOff = 0;

            len -= gapLen;
            inOff += gapLen;
            outOff += resultLen;

            int chunkSize = len - (len % buf.length);

            resultLen += translator.encode(in, inOff, chunkSize, out, outOff);

            len -= chunkSize;
            inOff += chunkSize;
        }

        if (len != 0)
        {
            System.arraycopy(in, inOff, buf, bufOff, len);

            bufOff += len;
        }

        return resultLen;
    }
}
