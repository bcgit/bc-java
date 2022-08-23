package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;

public class FrodoKEMExtractor
        implements EncapsulatedSecretExtractor
{
    private FrodoEngine engine;

    private FrodoKeyParameters key;

    public FrodoKEMExtractor(FrodoKeyParameters privParams)
    {
        this.key = privParams;
        initCipher(key.getParameters());
    }

    private void initCipher(FrodoParameters param)
    {
        engine = param.getEngine();
    }

    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        byte[] session_key = new byte[engine.getSessionKeySize()];
        engine.kem_dec(session_key, encapsulation, ((FrodoPrivateKeyParameters)key).getPrivateKey());
        return session_key;
    }

    public int getEncapsulationLength()
    {
        return engine.getCipherTextSize();
    }
}
