package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.mls.crypto.MlsCipherSuite;

public class Capabilities
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    static private final Short[] DEFAULT_SUPPORTED_VERSIONS = {ProtocolVersion.mls10.value};
    static private final short[] DEFAULT_SUPPORTED_CIPHERSUITES = MlsCipherSuite.ALL_SUPPORTED_SUITES;
    static private final Short[] DEFAULT_SUPPORTED_CREDENTIALS = {CredentialType.basic.value, CredentialType.x509.value};
    List<Short> versions;
    List<Short> cipherSuites;
    List<Short> extensions;
    List<Short> proposals;
    List<Short> credentials;

    public List<Short> getExtensions()
    {
        return extensions;
    }

    public Capabilities()
    {
        versions = Arrays.asList(DEFAULT_SUPPORTED_VERSIONS);
        cipherSuites = new ArrayList<Short>();
        for (short suite : DEFAULT_SUPPORTED_CIPHERSUITES)
        {
            cipherSuites.add(suite);
        }
        extensions = new ArrayList<Short>();
        proposals = new ArrayList<Short>();
        credentials = Arrays.asList(DEFAULT_SUPPORTED_CREDENTIALS);
    }

    @SuppressWarnings("unused")
    Capabilities(MLSInputStream stream)
        throws IOException
    {
        versions = new ArrayList<Short>();
        cipherSuites = new ArrayList<Short>();
        extensions = new ArrayList<Short>();
        proposals = new ArrayList<Short>();
        credentials = new ArrayList<Short>();
        stream.readList(versions, short.class);
        stream.readList(cipherSuites, short.class);
        stream.readList(extensions, short.class);
        stream.readList(proposals, short.class);
        stream.readList(credentials, short.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.writeList(versions);
        stream.writeList(cipherSuites);
        stream.writeList(extensions);
        stream.writeList(proposals);
        stream.writeList(credentials);
    }
}
