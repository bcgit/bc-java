package org.bouncycastle.pqc.crypto.sphincs;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class SPHINCSPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private final byte[] keyData;

    public SPHINCSPrivateKeyParameters(byte[] keyData)
    {
        super(true);
        this.keyData = Arrays.clone(keyData);
    }

    public byte[] getKeyData()
    {
        return Arrays.clone(keyData);
    }
}
