package org.bouncycastle.mls.codec;

import java.io.IOException;

public class ExternalSender
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    public byte[] signatureKey;
    Credential credential;

    public ExternalSender(byte[] signatureKey, Credential credential)
    {
        this.signatureKey = signatureKey;
        this.credential = credential;
    }

    public ExternalSender(MLSInputStream stream) throws IOException
    {
        signatureKey = stream.readOpaque();
        credential = (Credential) stream.read(Credential.class);
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(signatureKey);
        stream.write(credential);
    }
}