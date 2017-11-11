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


import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;

import com.github.gv2011.util.bytes.Bytes;

class StreamUtil
{
    private static final long  MAX_MEMORY = Runtime.getRuntime().maxMemory();

    /**
     * Find out possible longest length...
     *
     * @param in input stream of interest
     * @return length calculation or MAX_VALUE.
     */
    static int findLimit(final InputStream in)
    {
        if (in instanceof LimitedInputStream)
        {
            return ((LimitedInputStream)in).getRemaining();
        }
        else if (in instanceof ASN1InputStream)
        {
            return ((ASN1InputStream)in).getLimit();
        }
        else if (in instanceof ByteArrayInputStream)
        {
            return ((ByteArrayInputStream)in).available();
        }
        else if (in instanceof FileInputStream)
        {
            try
            {
                final FileChannel channel = ((FileInputStream)in).getChannel();
                final long  size = (channel != null) ? channel.size() : Integer.MAX_VALUE;

                if (size < Integer.MAX_VALUE)
                {
                    return (int)size;
                }
            }
            catch (final IOException e)
            {
                // ignore - they'll find out soon enough!
            }
        }

        if (MAX_MEMORY > Integer.MAX_VALUE)
        {
            return Integer.MAX_VALUE;
        }

        return (int)MAX_MEMORY;
    }

    static int typicalLength(final Bytes encoded){
      return 1 + calculateBodyLength(encoded.size()) + encoded.size();
    }

    static int calculateBodyLength(final int length){
      int count = 1;
      if (length > 127){
        int size = 1;
        int val = length;
        while ((val >>>= 8) != 0) size++;
        for (int i = (size - 1) * 8; i >= 0; i -= 8) count++;
      }
      return count;
    }

    static int calculateTagLength(int tagNo)
    {
        int length = 1;

        if (tagNo >= 31)
        {
            if (tagNo < 128)
            {
                length++;
            }
            else
            {
                final byte[] stack = new byte[5];
                int pos = stack.length;

                stack[--pos] = (byte)(tagNo & 0x7F);

                do
                {
                    tagNo >>= 7;
                    stack[--pos] = (byte)(tagNo & 0x7F | 0x80);
                }
                while (tagNo > 127);

                length += stack.length - pos;
            }
        }

        return length;
    }
}
