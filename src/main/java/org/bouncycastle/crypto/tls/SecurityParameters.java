package org.bouncycastle.crypto.tls;

public class SecurityParameters
{
    int prfAlgorithm = -1;
    byte[] clientRandom = null;
    byte[] serverRandom = null;
    byte[] masterSecret = null;

    public int getPrfAlgorithm()
    {
        return prfAlgorithm;
    }

    public byte[] getClientRandom()
    {
        return clientRandom;
    }

    public byte[] getServerRandom()
    {
        return serverRandom;
    }

    public byte[] getMasterSecret()
    {
        return masterSecret;
    }
}
