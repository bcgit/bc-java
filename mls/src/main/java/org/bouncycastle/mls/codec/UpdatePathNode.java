package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class UpdatePathNode
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    public byte[] encryption_key;

    public List<HPKECiphertext> encrypted_path_secret;

    public UpdatePathNode(byte[] encryption_key, List<HPKECiphertext> encrypted_path_secret)
    {
        this.encryption_key = encryption_key;
        this.encrypted_path_secret = encrypted_path_secret;
    }

    UpdatePathNode(MLSInputStream stream) throws IOException
    {
        encryption_key = stream.readOpaque();
        encrypted_path_secret = new ArrayList<>();
        stream.readList(encrypted_path_secret, HPKECiphertext.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(encryption_key);
        stream.writeList(encrypted_path_secret);
    }
}
