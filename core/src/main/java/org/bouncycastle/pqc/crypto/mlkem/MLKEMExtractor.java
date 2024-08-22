package org.bouncycastle.pqc.crypto.mlkem;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class MLKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private MLKEMEngine engine;

    private MLKEMPrivateKeyParameters key;

    public MLKEMExtractor(MLKEMPrivateKeyParameters privParams)
    {
        this.key = privParams;
        initCipher(privParams);
    }

    private void initCipher(AsymmetricKeyParameter recipientKey)
    {
        MLKEMPrivateKeyParameters key = (MLKEMPrivateKeyParameters)recipientKey;
        engine = key.getParameters().getEngine();
    }

    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        // Decryption
        byte[] sharedSecret = engine.kemDecrypt(key.getEncoded(), encapsulation);
        return sharedSecret;
    }

    public int getEncapsulationLength()
    {
        return engine.getCryptoCipherTextBytes();
    }
}
