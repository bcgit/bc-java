package org.bouncycastle.crypto.tls;

import org.bouncycastle.util.Arrays;

public final class SessionParameters
{
    private final int cipherSuite;
    private final short compressionAlgorithm;
    private final byte[] masterSecret;

    public SessionParameters(int cipherSuite, short compressionAlgorithm, byte[] masterSecret)
    {
        this.cipherSuite = cipherSuite;
        this.compressionAlgorithm = compressionAlgorithm;
        this.masterSecret = Arrays.clone(masterSecret);
    }

    public SessionParameters(SecurityParameters securityParameters)
    {
        if (securityParameters == null)
        {
            throw new IllegalArgumentException("'securityParameters' cannot be null");
        }

        this.cipherSuite = securityParameters.getCipherSuite();
        this.compressionAlgorithm = securityParameters.getCompressionAlgorithm();
        this.masterSecret = Arrays.clone(securityParameters.getMasterSecret());
    }

    public void clear()
    {
        if (this.masterSecret != null)
        {
            Arrays.fill(this.masterSecret, (byte)0);
        }
    }

    public SessionParameters copy()
    {
        return new SessionParameters(cipherSuite, compressionAlgorithm, masterSecret);
    }

    public int getCipherSuite()
    {
        return cipherSuite;
    }

    public short getCompressionAlgorithm()
    {
        return compressionAlgorithm;
    }

    public byte[] getMasterSecret()
    {
        return masterSecret;
    }
}
