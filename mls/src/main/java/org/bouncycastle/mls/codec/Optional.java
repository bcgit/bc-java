package org.bouncycastle.mls.codec;

import org.bouncycastle.mls.TreeKEM.Node;

import java.io.IOException;

public class Optional<T>
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    private T value;
    public Optional(MLSInputStream stream) throws IOException
    {
        value = (T) stream.readOptional(value.getClass());
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOptional(value);
    }
}
