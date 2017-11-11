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


import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;
import static com.github.gv2011.util.ex.Exceptions.call;
import static com.github.gv2011.util.ex.Exceptions.run;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

/**
 * Utility methods to assist with stream processing.
 */
public final class Streams
{
    private static int BUFFER_SIZE = 4096;

    /**
     * Read stream till EOF is encountered.
     *
     * @param inStr stream to be emptied.
     * @throws IOException in case of underlying IOException.
     */
    public static void drain(final InputStream inStr){
      run(()->{
        final byte[] bs = new byte[BUFFER_SIZE];
        while (inStr.read(bs, 0, bs.length) >= 0){}
      });
    }

    /**
     * Read stream fully, returning contents in a byte array.
     *
     * @param inStr stream to be read.
     * @return a byte array representing the contents of inStr.
     * @throws IOException in case of underlying IOException.
     */
    public static Bytes readAll(final InputStream inStr){
      final BytesBuilder buf = newBytesBuilder();
      pipeAll(inStr, buf);
      return buf.build();
    }

    /**
     * Read from inStr up to a maximum number of bytes, throwing an exception if more the maximum amount
     * of requested data is available.
     *
     * @param inStr stream to be read.
     * @param limit maximum number of bytes that can be read.
     * @return a byte array representing the contents of inStr.
     * @throws IOException in case of underlying IOException, or if limit is reached on inStr still has data in it.
     */
    public static byte[] readAllLimited(final InputStream inStr, final int limit){
        final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        pipeAllLimited(inStr, limit, buf);
        return buf.toByteArray();
    }

    /**
     * Fully read in buf's length in data, or up to EOF, whichever occurs first,
     *
     * @param inStr the stream to be read.
     * @param buf the buffer to be read into.
     * @return the number of bytes read into the buffer.
     * @throws IOException in case of underlying IOException.
     */
    public static int readFully(final InputStream inStr, final byte[] buf){
        return readFully(inStr, buf, 0, buf.length);
    }

    /**
     * Fully read in len's bytes of data into buf, or up to EOF, whichever occurs first,
     *
     * @param inStr the stream to be read.
     * @param buf the buffer to be read into.
     * @param off offset into buf to start putting bytes into.
     * @param len  the number of bytes to be read.
     * @return the number of bytes read into the buffer.
     * @throws IOException in case of underlying IOException.
     */
    public static int readFully(final InputStream inStr, final byte[] buf, final int off, final int len){
      return call(()->{
        int totalRead = 0;
        while (totalRead < len)
        {
            final int numRead = inStr.read(buf, off + totalRead, len - totalRead);
            if (numRead < 0)
            {
                break;
            }
            totalRead += numRead;
        }
        return totalRead;
      });
    }

    /**
     * Write the full contents of inStr to the destination stream outStr.
     *
     * @param inStr source input stream.
     * @param outStr destination output stream.
     * @throws IOException in case of underlying IOException.
     */
    public static void pipeAll(final InputStream inStr, final OutputStream outStr){
      run(()->{
        final byte[] bs = new byte[BUFFER_SIZE];
        int numRead;
        while ((numRead = inStr.read(bs, 0, bs.length)) >= 0)
        {
            outStr.write(bs, 0, numRead);
        }
      });
    }

    /**
     * Write up to limit bytes of data from inStr to the destination stream outStr.
     *
     * @param inStr source input stream.
     * @param limit the maximum number of bytes allowed to be read.
     * @param outStr destination output stream.
     * @throws IOException in case of underlying IOException, or if limit is reached on inStr still has data in it.
     */
    public static long pipeAllLimited(final InputStream inStr, final long limit, final OutputStream outStr){
      return call(()->{
        long total = 0;
        final byte[] bs = new byte[BUFFER_SIZE];
        int numRead;
        while ((numRead = inStr.read(bs, 0, bs.length)) >= 0)
        {
            if ((limit - total) < numRead)
            {
                throw new StreamOverflowException("Data Overflow");
            }
            total += numRead;
            outStr.write(bs, 0, numRead);
        }
        return total;
      });
    }
}
