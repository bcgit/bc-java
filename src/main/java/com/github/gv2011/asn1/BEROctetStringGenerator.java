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


import static com.github.gv2011.util.bytes.ByteUtils.newBytes;

import java.io.IOException;
import java.io.OutputStream;

public class BEROctetStringGenerator
    extends BERGenerator
{
    public BEROctetStringGenerator(final OutputStream out)
        throws IOException
    {
        super(out);

        writeBERHeader(BERTags.CONSTRUCTED | BERTags.OCTET_STRING);
    }

    public BEROctetStringGenerator(
        final OutputStream out,
        final int tagNo,
        final boolean isExplicit)
        throws IOException
    {
        super(out, tagNo, isExplicit);

        writeBERHeader(BERTags.CONSTRUCTED | BERTags.OCTET_STRING);
    }

    public OutputStream getOctetOutputStream()
    {
        return getOctetOutputStream();
    }

    @SuppressWarnings("unused") //TODO delete
    private class BufferedBEROctetStream
        extends OutputStream
    {
        private final byte[] _buf = new byte[1000];// limit for CER encoding.
        private int    _off;
        private final DEROutputStream _derOut;

        BufferedBEROctetStream()
        {
            _off = 0;
            _derOut = new DEROutputStream(_out);
        }

        @Override
        public void write(
            final int b)
            throws IOException
        {
            _buf[_off++] = (byte)b;

            if (_off == _buf.length)
            {
                DEROctetString.encode(_derOut, newBytes(_buf));
                _off = 0;
            }
        }

        @Override
        public void write(final byte[] b, int off, int len) throws IOException
        {
            while (len > 0)
            {
                final int numToCopy = Math.min(len, _buf.length - _off);
                System.arraycopy(b, off, _buf, _off, numToCopy);

                _off += numToCopy;
                if (_off < _buf.length)
                {
                    break;
                }

                DEROctetString.encode(_derOut, newBytes(_buf));
                _off = 0;

                off += numToCopy;
                len -= numToCopy;
            }
        }

        @Override
        public void close()
            throws IOException
        {
            if (_off != 0)
            {
                final byte[] bytes = new byte[_off];
                System.arraycopy(_buf, 0, bytes, 0, _off);

                DEROctetString.encode(_derOut, newBytes(bytes));
            }

             writeBEREnd();
        }
    }
}
