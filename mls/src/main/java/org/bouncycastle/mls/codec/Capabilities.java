package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Capabilities
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    List<Short> versions;
    List<Short> cipherSuites;
    List<Short> extensions;
    List<Short> proposals;
    List<Short> credentials;

    Capabilities(MLSInputStream stream) throws IOException
    {
        versions = new ArrayList<>();
        cipherSuites = new ArrayList<>();
        extensions = new ArrayList<>();
        proposals = new ArrayList<>();
        credentials = new ArrayList<>();
        stream.readList(versions, short.class);
        stream.readList(cipherSuites, short.class);
        stream.readList(extensions, short.class);
        stream.readList(proposals, short.class);
        stream.readList(credentials, short.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeList(versions);
        stream.writeList(cipherSuites);
        stream.writeList(extensions);
        stream.writeList(proposals);
        stream.writeList(credentials);
    }
}
