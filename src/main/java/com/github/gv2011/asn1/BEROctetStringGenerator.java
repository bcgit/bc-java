package com.github.gv2011.asn1;

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
