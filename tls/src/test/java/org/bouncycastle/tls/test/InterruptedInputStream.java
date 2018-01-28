package org.bouncycastle.tls.test;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.util.Random;

class InterruptedInputStream extends FilterInputStream
{
    private final Random random;

    private volatile int percentInterrupted = 0;

    public InterruptedInputStream(InputStream input, Random random)
    {
        super(input);

        if (random == null)
        {
            throw new NullPointerException("'random' cannot be null");
        }

        this.random = random;
    }

    public int getPercentInterrupted()
    {
        return percentInterrupted;
    }

    public void setPercentInterrupted(int percentInterrupted)
    {
        if (percentInterrupted < 0 || percentInterrupted > 100)
        {
            throw new IllegalArgumentException("'percentInterrupted' out of range");
        }

        this.percentInterrupted = percentInterrupted;
    }

    public int read() throws IOException
    {
        randomInterrupt();
        return in.read();
    }

    public int read(byte[] b) throws IOException
    {
        randomInterrupt();
        return in.read(b);
    }

    public int read(byte[] b, int off, int len) throws IOException
    {
        randomInterrupt();
        return in.read(b, off, len);
    }

    protected void randomInterrupt()
        throws InterruptedIOException
    {
        if (percentInterrupted > 0 && random.nextInt(100) < percentInterrupted)
        {
            throw new InterruptedIOException();
        }
    }
}
