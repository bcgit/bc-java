package org.bouncycastle.pqc.crypto.sphincs;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class SPHINCSPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final byte[] keyData;

    public SPHINCSPublicKeyParameters(byte[] keyData)
    {
        super(false);
        this.keyData = Arrays.clone(keyData);
    }

    public byte[] getKeyData()
    {
        return Arrays.clone(keyData);
    }
}
