package org.bouncycastle.pqc.crypto.snova;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class SnovaPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final byte[] publicKey;
    private final SnovaParameters parameters;

    public SnovaPublicKeyParameters(SnovaParameters parameters, byte[] publicKey)
    {
        super(false);

        if (publicKey.length != parameters.getPublicKeyLength())
        {
            throw new IllegalArgumentException("'publicKey' has invalid length");
        }

        this.publicKey = Arrays.clone(publicKey);
        this.parameters = parameters;
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(publicKey);
    }

    public SnovaParameters getParameters()
    {
        return parameters;
    }
}
