package org.bouncycastle.mls.crypto;

import java.io.IOException;

import org.bouncycastle.crypto.Digest;

public interface MlsKdf
{
    int getHashLength();

    public Digest getDigest();

    byte[] extract(byte[] salt, byte[] ikm);

    byte[] expand(byte[] prk, byte[] info, int length);

    byte[] expandWithLabel(byte[] secret, String label, byte[] context, int length)
        throws IOException;

}
