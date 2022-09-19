package org.bouncycastle.pqc.crypto.hqc;


import org.bouncycastle.crypto.EncapsulatedSecretExtractor;

public class HQCKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private HQCEngine engine;

    private HQCKeyParameters key;

    public HQCKEMExtractor(HQCPrivateKeyParameters privParams)
    {
        this.key = privParams;
        initCipher(key.getParameters());
    }

    private void initCipher(HQCParameters param)
    {
        engine = param.getEngine();
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        byte[] session_key = new byte[engine.getSessionKeySize()];
        HQCPrivateKeyParameters secretKey = (HQCPrivateKeyParameters)key;
        byte[] sk = secretKey.getPrivateKey();

        engine.decaps(session_key, encapsulation, sk);

        return session_key;
    }

    public int getEncapsulationLength()
    {
        return key.getParameters().getN_BYTES() + key.getParameters().getN1N2_BYTES();
    }
}
