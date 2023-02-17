package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public abstract class KEMKeyWrapper
    implements KeyWrapper
{
    private AlgorithmIdentifier algorithmId;

    protected KEMKeyWrapper(AlgorithmIdentifier algorithmId)
    {
        this.algorithmId = algorithmId;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmId;
    }

    public abstract byte[] getEncapsulation();

    public abstract AlgorithmIdentifier getKdfAlgorithmIdentifier();

    public abstract int getKekLength();

    public abstract AlgorithmIdentifier getWrapAlgorithmIdentifier();
}
