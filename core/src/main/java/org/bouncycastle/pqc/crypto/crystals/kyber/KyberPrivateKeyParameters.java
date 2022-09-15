package org.bouncycastle.pqc.crypto.crystals.kyber;

import org.bouncycastle.util.Arrays;

public class KyberPrivateKeyParameters
    extends KyberKeyParameters
{
    final byte[] privateKey;
    final byte[] publicKey;

    public KyberPrivateKeyParameters(KyberParameters params, byte[] privateKey, byte[] publicKey)
    {
        super(true, params);
        this.privateKey = Arrays.clone(privateKey);
        this.publicKey = publicKey;
    }

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }
}
