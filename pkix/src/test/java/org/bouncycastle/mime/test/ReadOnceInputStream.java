package org.bouncycastle.mime.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * File to guarantee no back tracking...
 */
public class ReadOnceInputStream
    extends ByteArrayInputStream
{
    public ReadOnceInputStream(byte[] buf)
    {
        super(buf);
    }

    public boolean markSupported()
    {
        return false;
    }

    int currPos = -22;

    public int read()
    {
        if (0 > currPos)
        {
            currPos = 0;
        }
        currPos++;

        return super.read();
    }

    public int read(byte b[], int off, int len)
    {
        if (off < currPos)
        {
            throw new RuntimeException("off " + off + " > currPos " + currPos);
        }
        currPos = off;
        int res = super.read(b, off, len);
        if (res < 0)
        {
            throw new RuntimeException("off " + off + " > currPos " + currPos + " res " + res);
        }
        currPos += res;
        return res;
    }

    public int read(byte b[])
        throws IOException
    {
        int res = super.read(b);
        currPos += res;
        return res;
    }
}