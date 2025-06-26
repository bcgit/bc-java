package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;

public class ParametersWithDigest
    implements CipherParameters
{
    private CipherParameters  parameters;
    private Digest digest;

    public ParametersWithDigest(
            CipherParameters parameters,
            Digest digest)
    {
        if (digest == null)
        {
            throw new NullPointerException("'digest' cannot be null");
        }

        this.parameters = parameters;
        this.digest = digest;
    }

    public Digest getDigest()
    {
        return digest;
    }

    public CipherParameters getParameters()
    {
        return parameters;
    }
}
