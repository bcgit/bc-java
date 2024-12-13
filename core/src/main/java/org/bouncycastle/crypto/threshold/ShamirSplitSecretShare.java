package org.bouncycastle.crypto.threshold;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

public class ShamirSplitSecretShare
    implements SecretShare
{
    private final byte[] secretShare;
    final int r; // index of secretShare

    public ShamirSplitSecretShare(byte[] secretShare, int r)
    {
        this.secretShare = Arrays.clone(secretShare);
        this.r = r;
    }

    public ShamirSplitSecretShare(byte[] secretShare)
    {
        this.secretShare = Arrays.clone(secretShare);
        this.r = 1;
    }

    @Override
    public byte[] getEncoded()
        throws IOException
    {
        return Arrays.clone(secretShare);
    }
}
