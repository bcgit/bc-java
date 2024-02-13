package org.bouncycastle.mls.TreeKEM;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoField;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

public class LifeTime
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    private final long not_before;
    private final long not_after;

    @SuppressWarnings("unused")
    public LifeTime(MLSInputStream stream)
        throws IOException
    {
        not_before = (long)stream.read(long.class);
        not_after = (long)stream.read(long.class);
    }

    public LifeTime()
    {
        //TODO: should be Long.MAX_VALUE but this might interfere up testing with test vectors using unsigned long
//        this.not_before = System.currentTimeMillis() / 1000L;
//        this.not_after = not_before + 31536000; // one year

        //TODO: remove after testing
        this.not_before = 0;
        this.not_after = -1;
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(not_before);
        stream.write(not_after);
    }

    protected boolean verify()
    {
        long now = Instant.now().getLong(ChronoField.INSTANT_SECONDS);
        if (not_after == -1)
        {
            return (now >= not_before) && (now < Long.MAX_VALUE);
        }
        return (now >= not_before) && (now < not_after);
    }
}
