package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.Optional;
import org.bouncycastle.mls.codec.PathSecret;
import org.bouncycastle.mls.codec.UpdatePath;

import java.io.IOException;
import java.util.List;

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
