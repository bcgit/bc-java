package org.bouncycastle.pqc.crypto.hawk;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Common base for Hawk public and private key parameter classes; carries the
 * {@link HawkParameters} parameter set the key belongs to.
 */
public class HawkKeyParameters
    extends AsymmetricKeyParameter
{
    private final HawkParameters params;

    public HawkKeyParameters(
        boolean isPrivate,
        HawkParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public HawkParameters getParameters()
    {
        return params;
    }
}
