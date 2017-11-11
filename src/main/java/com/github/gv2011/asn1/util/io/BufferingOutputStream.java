package com.github.gv2011.asn1.util.io;

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


import static com.github.gv2011.util.ex.Exceptions.run;

import java.io.OutputStream;

import com.github.gv2011.asn1.util.Arrays;

/**
 * An output stream that buffers data to be feed into an encapsulated output stream.
 * <p>
 * The stream zeroes out the internal buffer on each flush.
 * </p>
 */
public class BufferingOutputStream
    extends OutputStream
{
    private final OutputStream other;
    private final byte[] buf;

    private int   bufOff;

    /**
     * Create a buffering stream with the default buffer size (4096).
     *
     * @param other output stream to be wrapped.
     */
    public BufferingOutputStream(final OutputStream other)
    {
        this.other = other;
        buf = new byte[4096];
    }

    /**
     * Create a buffering stream with a specified buffer size.
     *
     * @param other output stream to be wrapped.
     * @param bufferSize size in bytes for internal buffer.
     */
    public BufferingOutputStream(final OutputStream other, final int bufferSize)
    {
        this.other = other;
        buf = new byte[bufferSize];
    }

    @Override
    public void write(final byte[] bytes, int offset, int len){
        if (len < buf.length - bufOff)
        {
            System.arraycopy(bytes, offset, buf, bufOff, len);
            bufOff += len;
        }
        else
        {
            final int gap = buf.length - bufOff;

            System.arraycopy(bytes, offset, buf, bufOff, gap);
            bufOff += gap;

            flush();

            offset += gap;
            len -= gap;
            while (len >= buf.length)
            {
                final int off = offset;
                run(()->other.write(bytes, off, buf.length));
                offset += buf.length;
                len -= buf.length;
            }

            if (len > 0)
            {
                System.arraycopy(bytes, offset, buf, bufOff, len);
                bufOff += len;
            }
        }
    }

    @Override
    public void write(final int b){
        buf[bufOff++] = (byte)b;
        if (bufOff == buf.length)
        {
            flush();
        }
    }

    /**
     * Flush the internal buffer to the encapsulated output stream. Zero the buffer contents when done.
     *
     * @throws IOException on error.
     */
    @Override
    public void flush(){
        run(()->other.write(buf, 0, bufOff));
        bufOff = 0;
        Arrays.fill(buf, (byte)0);
    }

    @Override
    public void close(){
        try{flush();}
        finally{run(other::close);}
    }
}
