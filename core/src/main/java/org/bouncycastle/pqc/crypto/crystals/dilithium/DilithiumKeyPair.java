package org.bouncycastle.pqc.crypto.crystals.dilithium;

public class DilithiumKeyPair<T>
{
    private final T publicKey;
    private final T secretKey;

    public DilithiumKeyPair(T publicKey, T secretKey)
    {
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }

    public T getPublicKey()
    {
        return publicKey;
    }

    public T getSecretKey()
    {
        return secretKey;
    }
}
