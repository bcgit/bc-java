package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

import java.io.IOException;

public class LifeTime
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    long not_before;
    long not_after;

    public LifeTime(MLSInputStream stream) throws IOException
    {
        not_before = (long) stream.read(long.class);
        not_after = (long) stream.read(long.class);
    }
    public LifeTime()
    {
        //TODO: should be Long.MAX_VALUE but this might interfere up testing with test vectors using unsigned long
        this.not_before = System.currentTimeMillis() / 1000L;
        this.not_after = not_before + 31536000; // one year

        //TODO: remove after testing
        this.not_before = 0;
        this.not_after = -1;
    }

    public LifeTime(long not_before, long not_after)
    {
        this.not_before = not_before;
        this.not_after = not_after;
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(not_before);
        stream.write(not_after);
    }
}
