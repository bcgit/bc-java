package org.bouncycastle.tls;

import java.math.BigInteger;

import org.bouncycastle.tls.crypto.TlsSRPConfig;

public class TlsSRPLoginParameters
{
    protected TlsSRPConfig srpConfig;
    protected BigInteger verifier;
    protected byte[] salt;

    public TlsSRPLoginParameters(TlsSRPConfig srpConfig, BigInteger verifier, byte[] salt)
    {
        this.srpConfig = srpConfig;
        this.verifier = verifier;
        this.salt = salt;
    }

    public TlsSRPConfig getConfig()
    {
        return srpConfig;
    }

    public byte[] getSalt()
    {
        return salt;
    }

    public BigInteger getVerifier()
    {
        return verifier;
    }
}
