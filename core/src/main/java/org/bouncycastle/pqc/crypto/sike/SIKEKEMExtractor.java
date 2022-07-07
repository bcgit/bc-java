package org.bouncycastle.pqc.crypto.sike;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;

public class SIKEKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private SIKEEngine engine;

    private SIKEKeyParameters key;

    public SIKEKEMExtractor(SIKEPrivateKeyParameters privParams)
    {
        this.key = privParams;
        initCipher(key.getParameters());
    }

    private void initCipher(SIKEParameters param)
    {
        engine = param.getEngine();
        SIKEPrivateKeyParameters privateParams = (SIKEPrivateKeyParameters)key;
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        return extractSecret(encapsulation, engine.getDefaultSessionKeySize());
    }

    public byte[] extractSecret(byte[] encapsulation, int sessionKeySizeInBits)
    {
        byte[] session_key = new byte[sessionKeySizeInBits / 8];
        engine.crypto_kem_dec(session_key, encapsulation, ((SIKEPrivateKeyParameters)key).getPrivateKey());
        return session_key;
    }

    public int getInputSize()
    {
        return engine.getCipherTextSize();
    }
}
