package org.bouncycastle.mls.codec;

import java.io.IOException;

public class PathSecret
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    public byte[] path_secret;

    public PathSecret(byte[] path_secret)
    {
        this.path_secret = path_secret;
    }

    PathSecret(MLSInputStream stream) throws IOException
    {
        path_secret = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(path_secret);
    }
}
