package org.bouncycastle.mls.codec;

import org.bouncycastle.mls.crypto.CipherSuite;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Capabilities
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    static private final Short[] DEFAULT_SUPPORTED_VERSIONS = { ProtocolVersion.mls10.value };
    static private final short[] DEFAULT_SUPPORTED_CIPHERSUITES = CipherSuite.ALL_SUPPORTED_SUITES;
    static private final Short[] DEFAULT_SUPPORTED_CREDENTIALS = { CredentialType.basic.value, CredentialType.x509.value};
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
        //TODO: make default to support all
        versions = Arrays.asList(DEFAULT_SUPPORTED_VERSIONS);
        cipherSuites = new ArrayList<>();
        for (short suite : DEFAULT_SUPPORTED_CIPHERSUITES)
        {
            cipherSuites.add(suite);
        }
        extensions = new ArrayList<>();
        proposals = new ArrayList<>();
        credentials = Arrays.asList(DEFAULT_SUPPORTED_CREDENTIALS);
    }
    @SuppressWarnings("unused")
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
        stream.writeList(removeGREASE(versions));
        stream.writeList(removeGREASE(cipherSuites));
        stream.writeList(removeGREASE(extensions));
        stream.writeList(removeGREASE(proposals));
        stream.writeList(removeGREASE(credentials));
    }

    private List<Short> removeGREASE(List<Short> target)
    {
        List<Short> out = new ArrayList<>(target);
        for (int i = 0; i < target.size(); i++)
        {
            if (Grease.isGrease(target.get(i))!= -1)
            {
                out.remove(target.get(i));
            }
        }
        return out;
    }
}
