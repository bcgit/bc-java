package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A generator for indefinite-length OCTET STRINGs
 */
public class BEROctetStringGenerator
    extends BERGenerator
{
    /**
     * Use the passed in stream as the target for the generator, writing out the header tag
     * for a constructed OCTET STRING.
     *
     * @param out target stream
     * @throws IOException if the target stream cannot be written to.
     */
    public BEROctetStringGenerator(OutputStream out) 
        throws IOException
    {
        super(out);

        writeBERHeader(BERTags.CONSTRUCTED | BERTags.OCTET_STRING);
    }

    /**
     * Use the passed in stream as the target for the generator, writing out the header tag
     * for a tagged constructed OCTET STRING (possibly implicit).
     *
     * @param out target stream
     * @param tagNo the tag number to introduce
     * @param isExplicit true if this is an explicitly tagged object, false otherwise.
     * @throws IOException if the target stream cannot be written to.
     */
    public BEROctetStringGenerator(
        OutputStream out,
        int tagNo,
        boolean isExplicit) 
        throws IOException
    {
        super(out, tagNo, isExplicit);

        writeBERHeader(BERTags.CONSTRUCTED | BERTags.OCTET_STRING);
    }

    /**
     * Return a stream representing the content target for this OCTET STRING
     *
     * @return an OutputStream which chunks data in blocks of 1000 (CER limit).
     */
    public OutputStream getOctetOutputStream()
    {
        return getOctetOutputStream(new byte[1000]); // limit for CER encoding.
    }

    /**
     * Return a stream representing the content target for this OCTET STRING
     *
     * @param buf the buffer to use for chunking the data.
     * @return an OutputStream which chunks data in blocks of buf length.
     */
    public OutputStream getOctetOutputStream(
        byte[] buf)
    {
        return new BufferedBEROctetStream(buf);
    }

    private class BufferedBEROctetStream
        extends OutputStream
    {
        private byte[] _buf;
        private int    _off;
        private DEROutputStream _derOut;

        BufferedBEROctetStream(
            byte[] buf)
        {
            _buf = buf;
            _off = 0;
            _derOut = new DEROutputStream(_out);
        }

        public void write(
            int b)
            throws IOException
        {
            _buf[_off++] = (byte)b;

            if (_off == _buf.length)
            {
                DEROctetString.encode(_derOut, true, _buf, 0, _buf.length);
                _off = 0;
            }
        }

        public void write(byte[] b, int off, int len) throws IOException
        {
            int bufLen = _buf.length;
            int available = bufLen - _off;
            if (len < available)
            {
                System.arraycopy(b, off, _buf, _off, len);
                _off += len;
                return;
            }

            int count = 0;
            if (_off > 0)
            {
                System.arraycopy(b, off, _buf, _off, available);
                count += available;
                DEROctetString.encode(_derOut, true, _buf, 0, bufLen);
            }

            int remaining;
            while ((remaining = (len - count)) >= bufLen)
            {
                DEROctetString.encode(_derOut, true, b, off + count, bufLen);
                count += bufLen;
            }

            System.arraycopy(b, off + count, _buf, 0, remaining);
            this._off = remaining;
        }

        public void close()
            throws IOException
        {
            if (_off != 0)
            {
                DEROctetString.encode(_derOut, true, _buf, 0, _off);
            }

            _derOut.flushInternal();

             writeBEREnd();
        }
    }
}
