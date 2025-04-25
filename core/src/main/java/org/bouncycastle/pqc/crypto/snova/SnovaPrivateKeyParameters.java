package org.bouncycastle.pqc.crypto.snova;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class SnovaPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private final byte[] privateKey;
    private final SnovaParameters parameters;

    public SnovaPrivateKeyParameters(SnovaParameters parameters, byte[] privateKey)
    {
        super(true);
        this.privateKey = Arrays.clone(privateKey);
        this.parameters = parameters;
    }

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }

    public SnovaParameters getParameters()
    {
        return parameters;
    }
}
