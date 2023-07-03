package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Credential
        implements MLSInputStream.Readable, MLSOutputStream.Writable

{
    public CredentialType credentialType;
    byte[] identity;
    List<Certificate> certificates;

    Credential(MLSInputStream stream) throws IOException
    {
        this.credentialType = CredentialType.values()[(short) stream.read(short.class)];
        switch (credentialType)
        {
            case basic:
                identity = stream.readOpaque();
                break;
            case x509:
                certificates = new ArrayList<>();
                stream.readList(certificates, Certificate.class);
                break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(credentialType);
        switch (credentialType)
        {
            case basic:
                stream.writeOpaque(identity);
                break;
            case x509:
                stream.writeList(certificates);
                break;
        }
    }
}
