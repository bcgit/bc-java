package org.bouncycastle.mime.encoding;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.encoders.Base64Encoder;

public class Base64OutputStream
    extends FilterOutputStream
{
    private static final Base64Encoder ENCODER = new Base64Encoder();
    private static final int INBUF_SIZE = 54;
    private static final int OUTBUF_SIZE = (((INBUF_SIZE + 2) / 3) * 4) + 2;

    private final byte[] inBuf = new byte[INBUF_SIZE];
    private final byte[] outBuf = new byte[OUTBUF_SIZE];

    private int inPos = 0;

    public Base64OutputStream(OutputStream stream)
    {
        super(stream);

        outBuf[OUTBUF_SIZE - 2] = (byte)'\r';
        outBuf[OUTBUF_SIZE - 1] = (byte)'\n';
    }

    public void write(int b)
        throws IOException
    {
        inBuf[inPos++] = (byte)b;
        if (inPos == INBUF_SIZE)
        {
            encodeBlock(inBuf, 0);
            inPos = 0;
        }
    }

    public void write(byte[] buf, int off, int len)
        throws IOException
    {
        int available = INBUF_SIZE - inPos;
        if (len < available)
        {
            System.arraycopy(buf, off, inBuf, inPos, len);
            inPos += len;
            return;
        }

        int count = 0;
        if (inPos > 0)
        {
            System.arraycopy(buf, off, inBuf, inPos, available);
            count += available;
            encodeBlock(inBuf, 0);
//            inPos = 0;
        }

        int remaining;
        while ((remaining = (len - count)) >= INBUF_SIZE)
        {
            encodeBlock(buf, off + count);
            count += INBUF_SIZE;
        }

        System.arraycopy(buf, off + count, inBuf, 0, remaining);
        inPos = remaining;
    }

    public void write(byte[] buf)
        throws IOException
    {
        write(buf, 0, buf.length);
    }

    public void close()
        throws IOException
    {
        if (inPos > 0)
        {
            int outPos = ENCODER.encode(inBuf, 0, inPos, outBuf, 0);
            inPos = 0;

            outBuf[outPos++] = (byte)'\r';
            outBuf[outPos++] = (byte)'\n';

            out.write(outBuf, 0, outPos);
        }

        out.close();
    }

    private void encodeBlock(byte[] buf, int off)
        throws IOException
    {
        ENCODER.encode(buf, off, INBUF_SIZE, outBuf, 0);
        out.write(outBuf, 0, OUTBUF_SIZE);
    }
}
