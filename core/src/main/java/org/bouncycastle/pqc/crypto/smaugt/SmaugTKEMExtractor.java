package org.bouncycastle.pqc.crypto.smaugt;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;

public class SmaugTKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final SmaugTPrivateKeyParameters key;
    private final SmaugTEngine engine;

    public SmaugTKEMExtractor(SmaugTPrivateKeyParameters privParams)
    {
        this.key = privParams;
        this.engine = key.getParameters().getEngine();
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        if (encapsulation.length != getEncapsulationLength())
        {
            throw new IllegalArgumentException("encapsulation wrong length");
        }

        byte[] sessionKey = new byte[engine.getSharedSecretBytes()];
        engine.cryptoKemDec(sessionKey, encapsulation, key.getPrivateKey());
        return sessionKey;
    }

    public int getEncapsulationLength()
    {
        return engine.getCipherTextBytes();
    }
}
