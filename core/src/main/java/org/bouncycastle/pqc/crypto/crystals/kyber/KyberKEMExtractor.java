package org.bouncycastle.pqc.crypto.crystals.kyber;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class KyberKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private KyberEngine engine;

    private KyberPrivateKeyParameters key;

    public KyberKEMExtractor(KyberPrivateKeyParameters privParams)
    {
        this.key = privParams;
        initCipher(privParams);
    }

    private void initCipher(AsymmetricKeyParameter recipientKey)
    {
        KyberPrivateKeyParameters key = (KyberPrivateKeyParameters)recipientKey;
        engine = key.getParameters().getEngine();
    }

    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        // Decryption
        byte[] sharedSecret = engine.kemDecrypt(encapsulation, key.getEncoded());
        return sharedSecret;
    }

    public int getEncapsulationLength()
    {
        return engine.getCryptoCipherTextBytes();
    }
}
