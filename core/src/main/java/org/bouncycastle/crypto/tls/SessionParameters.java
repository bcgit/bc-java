package org.bouncycastle.crypto.tls;

import org.bouncycastle.util.Arrays;

public final class SessionParameters
{
    private final Certificate peerCertificate;
    private final int cipherSuite;
    private final short compressionAlgorithm;
    private final byte[] masterSecret;

    public SessionParameters(Certificate peerCertificate, int cipherSuite, short compressionAlgorithm, byte[] masterSecret)
    {
        this.peerCertificate = peerCertificate;
        this.cipherSuite = cipherSuite;
        this.compressionAlgorithm = compressionAlgorithm;
        this.masterSecret = Arrays.clone(masterSecret);
    }

    public SessionParameters(Certificate peerCertificate, SecurityParameters securityParameters)
    {
        if (securityParameters == null)
        {
            throw new IllegalArgumentException("'securityParameters' cannot be null");
        }

        this.peerCertificate = peerCertificate;
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
        return new SessionParameters(peerCertificate, cipherSuite, compressionAlgorithm, masterSecret);
    }

    public Certificate getPeerCertificate()
    {
        return peerCertificate;
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
