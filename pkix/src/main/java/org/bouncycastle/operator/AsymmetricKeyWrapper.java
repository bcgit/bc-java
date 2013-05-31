package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public abstract class AsymmetricKeyWrapper
    implements KeyWrapper
{
    private AlgorithmIdentifier algorithmId;

    protected AsymmetricKeyWrapper(AlgorithmIdentifier algorithmId)
    {
        this.algorithmId = algorithmId;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmId;
    }
}
