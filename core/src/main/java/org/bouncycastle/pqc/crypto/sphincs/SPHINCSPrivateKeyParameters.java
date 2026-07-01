package org.bouncycastle.pqc.crypto.sphincs;

import org.bouncycastle.util.Arrays;

public class SPHINCSPrivateKeyParameters
    extends SPHINCSKeyParameters
{
    private final byte[] keyData;

    public SPHINCSPrivateKeyParameters(byte[] keyData)
    {
        super(true, null);

        if (keyData.length != SPHINCS256Config.CRYPTO_SECRETKEYBYTES)
        {
            throw new IllegalArgumentException("'keyData' has invalid length");
        }

        this.keyData = Arrays.clone(keyData);
    }

    public SPHINCSPrivateKeyParameters(byte[] keyData, String treeDigest)
    {
        super(true, treeDigest);

        if (keyData.length != SPHINCS256Config.CRYPTO_SECRETKEYBYTES)
        {
            throw new IllegalArgumentException("'keyData' has invalid length");
        }

        this.keyData = Arrays.clone(keyData);
    }

    public byte[] getKeyData()
    {
        return Arrays.clone(keyData);
    }
}
