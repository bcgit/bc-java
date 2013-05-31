package org.bouncycastle.crypto.tls;

public class SecurityParameters
{

    int entity = -1;
    int prfAlgorithm = -1;
    short compressionAlgorithm = -1;
    int verifyDataLength = -1;
    byte[] masterSecret = null;
    byte[] clientRandom = null;
    byte[] serverRandom = null;

    /**
     * @return {@link ConnectionEnd}
     */
    public int getEntity()
    {
        return entity;
    }

    /**
     * @return {@link PRFAlgorithm}
     */
    public int getPrfAlgorithm()
    {
        return prfAlgorithm;
    }

    /**
     * @return {@link CompressionMethod}
     */
    public short getCompressionAlgorithm()
    {
        return compressionAlgorithm;
    }

    public int getVerifyDataLength()
    {
        return verifyDataLength;
    }

    public byte[] getMasterSecret()
    {
        return masterSecret;
    }

    public byte[] getClientRandom()
    {
        return clientRandom;
    }

    public byte[] getServerRandom()
    {
        return serverRandom;
    }
}
