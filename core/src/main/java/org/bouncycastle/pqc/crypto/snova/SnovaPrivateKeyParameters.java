package org.bouncycastle.pqc.crypto.snova;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class SnovaPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private final byte[] privateKey;

    public SnovaPrivateKeyParameters(byte[] privateKey)
    {
        super(true);
        this.privateKey = Arrays.clone(privateKey);
    }

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }
}
