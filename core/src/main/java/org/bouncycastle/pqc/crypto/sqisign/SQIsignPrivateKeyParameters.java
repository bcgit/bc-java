package org.bouncycastle.pqc.crypto.sqisign;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class SQIsignPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private final byte[] privateKey;
    private final SQIsignParameters parameters;

    public SQIsignPrivateKeyParameters(SQIsignParameters parameters, byte[] privateKey)
    {
        super(true);

        if (privateKey.length != parameters.getPrivateKeyLength())
        {
            throw new IllegalArgumentException("'privateKey' has invalid length");
        }

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

    public SQIsignParameters getParameters()
    {
        return parameters;
    }
}
