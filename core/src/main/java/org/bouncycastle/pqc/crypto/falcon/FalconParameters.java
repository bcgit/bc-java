package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.crypto.CipherParameters;

public class FalconParameters
    implements CipherParameters
{
    public static final FalconParameters falcon_512 = new FalconParameters("falcon-512", 9, 40);
    public static final FalconParameters falcon_1024 = new FalconParameters("falcon-1024", 10, 40);

    private final String name;
    private final int logn;
    private final int nonce_length;

    private FalconParameters(String name, int logn, int nonce_length)
    {
        if (logn < 1 || logn > 10)
        {
            throw new IllegalArgumentException("Log N degree should be between 1 and 10");
        }
        this.name = name;
        this.logn = logn;
        this.nonce_length = nonce_length;
    }

    public int getLogN()
    {
        return logn;
    }

    int getNonceLength()
    {
        return nonce_length;
    }

    public String getName()
    {
        return name;
    }
}
