package org.bouncycastle.pqc.crypto.haetae;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Common base for HAETAE public and private key parameter classes; carries
 * the {@link HAETAEParameters} parameter set the key belongs to.
 */
public class HAETAEKeyParameters
    extends AsymmetricKeyParameter
{
    private final HAETAEParameters params;

    public HAETAEKeyParameters(
        boolean isPrivate,
        HAETAEParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public HAETAEParameters getParameters()
    {
        return params;
    }
}
