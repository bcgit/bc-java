package org.bouncycastle.crypto.kems;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.kems.frodo.FrodoKEMEngine;
import org.bouncycastle.crypto.params.FrodoKEMPrivateKeyParameters;

public class FrodoKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final FrodoKEMPrivateKeyParameters key;
    private final FrodoKEMEngine engine;

    public FrodoKEMExtractor(FrodoKEMPrivateKeyParameters privParams)
    {
        if (privParams == null)
        {
            throw new NullPointerException("'privParams' cannot be null");
        }

        this.key = privParams;
        this.engine = FrodoKEMEngine.getInstance(privParams.getParameters());
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        if (encapsulation.length != getEncapsulationLength())
        {
            throw new IllegalArgumentException("encapsulation wrong length");
        }

        byte[] session_key = new byte[engine.getSessionKeySize()];
        engine.kem_dec(session_key, encapsulation, key.getPrivateKey());
        return session_key;
    }

    public int getEncapsulationLength()
    {
        return engine.getCipherTextSize();
    }
}
