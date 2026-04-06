package org.bouncycastle.crypto.kems;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.kems.mlkem.MLKEMEngine;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;

public class MLKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final MLKEMPrivateKeyParameters privateKey;
    private final MLKEMEngine engine;

    public MLKEMExtractor(MLKEMPrivateKeyParameters privateKey)
    {
        if (privateKey == null)
        {
            throw new NullPointerException("'privateKey' cannot be null");
        }

        this.privateKey = privateKey;
        this.engine = MLKEMEngine.getInstance(privateKey.getParameters());
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        if (encapsulation.length != this.getEncapsulationLength())
        {
            throw new IllegalArgumentException("encapsulation wrong length");
        }
        return engine.kemDecrypt(privateKey, encapsulation);
    }

    public int getEncapsulationLength()
    {
        return engine.getCipherTextBytes();
    }
}
