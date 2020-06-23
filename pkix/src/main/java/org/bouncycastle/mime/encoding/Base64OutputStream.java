package org.bouncycastle.mime.encoding;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.encoders.Base64Encoder;

public class Base64OutputStream
    extends FilterOutputStream
{
    private static final Base64Encoder ENCODER = new Base64Encoder();
    private static final int BUF_SIZE = 54;

    private final byte[] inBuf = new byte[BUF_SIZE];
    private final byte[] outBuf = new byte[(((BUF_SIZE + 2) / 3) * 4) + 2];

    private int inPos = 0;

    public Base64OutputStream(OutputStream stream)
    {
        super(stream);
    }

    public void write(int b)
        throws IOException
    {
        inBuf[inPos] = (byte)b;
        if (++inPos == BUF_SIZE)
        {
            encode(inBuf, 0, BUF_SIZE);
            inPos = 0;
        }
    }

    public void write(byte[] buf, int off, int len)
        throws IOException
    {
//        for (int i = 0; i < len; ++i)
//        {
//            inBuf[inPos] = buf[off + i];
//            if (++inPos == BUF_SIZE)
//            {
//                encode(inBuf, 0, BUF_SIZE);
//                inPos = 0;
//            }
//        }

        int available = BUF_SIZE - inPos; 
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
            encode(inBuf, 0, BUF_SIZE);
//            inPos = 0;
        }

        int remaining;
        while ((remaining = (len - count)) >= BUF_SIZE)
        {
            encode(buf, off + count, BUF_SIZE);
            count += BUF_SIZE;
        }

        System.arraycopy(buf, off + count, inBuf, 0, remaining);
        this.inPos = remaining;
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
            encode(inBuf, 0, inPos);
        }

        out.close();
    }

    private void encode(byte[] buf, int off, int len)
        throws IOException
    {
        int pos = ENCODER.encode(buf, off, len, outBuf, 0);

        outBuf[pos++] = (byte)'\r';
        outBuf[pos++] = (byte)'\n';

        out.write(outBuf, 0, pos);
    }
}
