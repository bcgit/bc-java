package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Credential
    implements MLSInputStream.Readable, MLSOutputStream.Writable

{
    CredentialType credentialType;
    byte[] identity;
    List<Certificate> certificates;

    public CredentialType getCredentialType()
    {
        return credentialType;
    }

    public byte[] getIdentity()
    {
        return identity;
    }

    static public Credential forBasic(byte[] identity)
    {
        return new Credential(CredentialType.basic, identity, new ArrayList<Certificate>());
    }

    public Credential(CredentialType credentialType, byte[] identity, List<Certificate> certificates)
    {
        this.credentialType = credentialType;
        this.identity = identity;
        this.certificates = certificates;
    }

    @SuppressWarnings("unused")
    Credential(MLSInputStream stream)
        throws IOException
    {
        short credType = (short)stream.read(short.class);
        if (Grease.isGrease(credType) == -1)
        {
            this.credentialType = CredentialType.values()[credType];
        }
        else
        {
            this.credentialType = CredentialType.values()[3 + Grease.isGrease(credType)];
        }
        switch (credentialType)
        {
        case basic:
            identity = stream.readOpaque();
            break;
        case x509:
            certificates = new ArrayList<Certificate>();
            stream.readList(certificates, Certificate.class);
            break;
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        if (Grease.isGrease(credentialType.value) == -1)
        {
            stream.write(credentialType);
        }
        else
        {
            //TODO: check if we write grease values or not
        }
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
