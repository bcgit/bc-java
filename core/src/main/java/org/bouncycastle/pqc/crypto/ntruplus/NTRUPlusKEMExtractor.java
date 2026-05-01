package org.bouncycastle.pqc.crypto.ntruplus;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;

public class NTRUPlusKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final NTRUPlusPrivateKeyParameters privateKey;
    private final NTRUPlusEngine engine;

    public NTRUPlusKEMExtractor(NTRUPlusPrivateKeyParameters privateKey)
    {
        if (privateKey == null)
        {
            throw new NullPointerException("'privateKey' cannot be null");
        }

        this.privateKey = privateKey;
        this.engine = new NTRUPlusEngine(privateKey.getParameters());
    }

    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        byte[] ss = new byte[NTRUPlusEngine.SSBytes];
        engine.crypto_kem_dec(ss, 0, encapsulation, 0, privateKey.getEncoded(), 0);
        return ss;
    }

    @Override
    public int getEncapsulationLength()
    {
        return privateKey.getParameters().getCiphertextBytes();
    }
}
