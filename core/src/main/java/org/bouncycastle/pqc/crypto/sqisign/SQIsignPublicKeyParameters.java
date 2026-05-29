package org.bouncycastle.pqc.crypto.sqisign;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class SQIsignPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final byte[] publicKey;
    private final SQIsignParameters parameters;

    public SQIsignPublicKeyParameters(SQIsignParameters parameters, byte[] publicKey)
    {
        super(false);
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

    public SQIsignParameters getParameters()
    {
        return parameters;
    }
}
