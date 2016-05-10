package com.github.gv2011.bcasn.crypto;

public class EphemeralKeyPair
{
    private AsymmetricCipherKeyPair keyPair;
    private KeyEncoder publicKeyEncoder;

    public EphemeralKeyPair(AsymmetricCipherKeyPair keyPair, KeyEncoder publicKeyEncoder)
    {
        this.keyPair = keyPair;
        this.publicKeyEncoder = publicKeyEncoder;
    }

    public AsymmetricCipherKeyPair getKeyPair()
    {
        return keyPair;
    }

    public byte[] getEncodedPublicKey()
    {
        return publicKeyEncoder.getEncoded(keyPair.getPublic());
    }
}
