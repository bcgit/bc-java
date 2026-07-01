package org.bouncycastle.pqc.crypto.sphincs;

import org.bouncycastle.util.Arrays;

public class SPHINCSPublicKeyParameters
    extends SPHINCSKeyParameters
{
    private final byte[] keyData;

    public SPHINCSPublicKeyParameters(byte[] keyData)
    {
        super(false, null);

        if (keyData.length != SPHINCS256Config.CRYPTO_PUBLICKEYBYTES)
        {
            throw new IllegalArgumentException("'keyData' has invalid length");
        }

        this.keyData = Arrays.clone(keyData);
    }

    public SPHINCSPublicKeyParameters(byte[] keyData, String treeDigest)
    {

        super(false, treeDigest);

        if (keyData.length != SPHINCS256Config.CRYPTO_PUBLICKEYBYTES)
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
