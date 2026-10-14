package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.util.Arrays;

public class HQCKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final HQCPrivateKeyParameters privateKey;
    private final HQCEngine engine;

    public HQCKEMExtractor(HQCPrivateKeyParameters privateKey)
    {
        if (privateKey == null)
        {
            throw new NullPointerException("'privateKey' cannot be null");
        }

        this.privateKey = privateKey;
        this.engine = privateKey.getParameters().getEngine();
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        if (encapsulation.length != getEncapsulationLength())
        {
            throw new IllegalArgumentException("encapsulation wrong length");
        }
        byte[] session_key = new byte[64];

        engine.decaps(session_key, encapsulation, privateKey.getExpandedKey());

        return Arrays.copyOfRange(session_key, 0, 32);
    }

    public int getEncapsulationLength()
    {
        return engine.getCipherTextBytes();
    }
}
