package org.bouncycastle.crypto.agreement.kdf;

import org.bouncycastle.crypto.DerivationParameters;

/**
 * BSI Key Derivation Function Parameters for Session Keys (see BSI-TR-03111 Section 4.3.3)
 */
public class GSKKDFParameters
    implements DerivationParameters
{
    private final byte[] z;
    private final int startCounter;
    private final byte[] nonce;

    public GSKKDFParameters(byte[] z, int startCounter)
    {
        this(z, startCounter, null);
    }

    public GSKKDFParameters(byte[] z, int startCounter, byte[] nonce)
    {
        this.z = z;
        this.startCounter = startCounter;
        this.nonce = nonce;
    }

    public byte[] getZ()
    {
        return z;
    }

    public int getStartCounter()
    {
        return startCounter;
    }

    public byte[] getNonce()
    {
        return nonce;
    }
}
