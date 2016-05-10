package com.github.gv2011.bcasn.crypto.tls;

import java.math.BigInteger;

import com.github.gv2011.bcasn.crypto.params.SRP6GroupParameters;

public class TlsSRPLoginParameters
{
    protected SRP6GroupParameters group;
    protected BigInteger verifier;
    protected byte[] salt;

    public TlsSRPLoginParameters(SRP6GroupParameters group, BigInteger verifier, byte[] salt)
    {
        this.group = group;
        this.verifier = verifier;
        this.salt = salt;
    }

    public SRP6GroupParameters getGroup()
    {
        return group;
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
