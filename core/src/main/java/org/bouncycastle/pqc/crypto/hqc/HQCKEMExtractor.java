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
        byte[] session_key = new byte[64];
        byte[] sk = privateKey.getPrivateKey();

        engine.decaps(session_key, encapsulation, sk);

        return Arrays.copyOfRange(session_key, 0, 32);
    }

    public int getEncapsulationLength()
    {
        return engine.getCipherTextBytes();
    }
}
