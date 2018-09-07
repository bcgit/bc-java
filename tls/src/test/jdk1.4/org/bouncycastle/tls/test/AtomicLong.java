package org.bouncycastle.tls.test;

/**
 * For jdk1.4
 */
public class AtomicLong
{
    long counter = 0;

    public AtomicLong(long start)
    {
        this.counter = start;
    }

    public long getAndIncrement()
    {
        synchronized (this)
        {
            return counter++;
        }
    }
}
