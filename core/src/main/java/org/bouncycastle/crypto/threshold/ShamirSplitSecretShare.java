package org.bouncycastle.crypto.threshold;

import org.bouncycastle.util.Arrays;

public class ShamirSplitSecretShare
    implements SecretShare
{
    private final byte[] secretShare;
    private final int r; // index of secretShare

    public ShamirSplitSecretShare(byte[] secretShare, int r)
    {
        this.secretShare = Arrays.clone(secretShare);
        this.r = r;
    }

    public byte[] getSecretShare()
    {
        return secretShare;
    }
}
