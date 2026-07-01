package org.bouncycastle.pqc.crypto.saber;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;

public class SABERKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private SABEREngine engine;

    private SABERKeyParameters key;

    public SABERKEMExtractor(SABERKeyParameters privParams)
    {
        this.key = privParams;
        initCipher(key.getParameters());
    }
    private void initCipher(SABERParameters param)
    {
        engine = param.getEngine();
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        if (encapsulation.length != getEncapsulationLength())
        {
            throw new IllegalArgumentException("encapsulation wrong length");
        }
        byte[] session_key = new byte[engine.getSessionKeySize()];
        engine.crypto_kem_dec(session_key, encapsulation, ((SABERPrivateKeyParameters)key).getPrivateKey());
        return session_key;
    }
    public int getEncapsulationLength()
    {
        return engine.getCipherTextSize();
    }
}
