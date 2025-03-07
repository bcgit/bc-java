package org.bouncycastle.pqc.crypto.snova;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class SnovaPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final byte[] publicKey;

    public SnovaPublicKeyParameters(byte[] publicKey)
    {
        super(false);
        this.publicKey = Arrays.clone(publicKey);
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(publicKey);
    }
}
