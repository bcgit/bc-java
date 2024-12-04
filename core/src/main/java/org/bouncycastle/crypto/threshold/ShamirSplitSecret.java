package org.bouncycastle.crypto.threshold;

public class ShamirSplitSecret
    implements SplitSecret
{
    private ShamirSplitSecretShare[] secretShares;

    public ShamirSplitSecret(ShamirSplitSecretShare[] secretShares)
    {
        this.secretShares = secretShares;
    }

    public ShamirSplitSecretShare[] getSecretShare()
    {
        return secretShares;
    }
}
