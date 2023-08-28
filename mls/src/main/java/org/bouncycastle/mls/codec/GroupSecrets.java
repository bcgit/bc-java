package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class GroupSecrets
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{

    public byte[] joiner_secret;
    public PathSecret path_secret;
    public List<PreSharedKeyID> psks;

    GroupSecrets(MLSInputStream stream) throws IOException
    {
        joiner_secret = stream.readOpaque();
        path_secret = (PathSecret) stream.readOptional(PathSecret.class);
        psks = new ArrayList<>();
        stream.readList(psks, PreSharedKeyID.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(joiner_secret);
        stream.writeOptional(path_secret);
        stream.writeList(psks);
    }
}
