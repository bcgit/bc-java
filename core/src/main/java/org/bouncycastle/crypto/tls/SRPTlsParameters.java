package org.bouncycastle.crypto.tls;

import java.math.BigInteger;

public class SRPTlsParameters
{

    private BigInteger verifier;
    private byte[] salt;
    private BigInteger prime;
    private BigInteger generator;
    
    /**
     * Parameters needed for the server side of TLS-SRP.
     * @param verifier The client's verifier (denoted v in SRP)
     * @param salt The salt associated with the client's verifier (denoted s in SRP)
     * @param prime The safe prime associated with the client's verifier (denoted N in SRP)
     * @param generator The generator associated with the client's verifier (denoted g in SRP)
     */
    public SRPTlsParameters(BigInteger verifier, byte[] salt, BigInteger prime,
            BigInteger generator)
    {
        this.verifier = verifier;
        this.salt = salt;
        this.prime = prime;
        this.generator = generator;
    }

    public BigInteger getVerifier()
    {
        return verifier;
    }

    public byte[] getSalt()
    {
        return salt;
    }

    public BigInteger getPrime()
    {
        return prime;
    }

    public BigInteger getGenerator()
    {
        return generator;
    }
    
}
