package org.bouncycastle.pqc.crypto.aimer;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Common base for AIMer public and private key parameter classes; carries the
 * {@link AIMerParameters} parameter set the key belongs to.
 */
public class AIMerKeyParameters
    extends AsymmetricKeyParameter
{
    private final AIMerParameters params;

    public AIMerKeyParameters(
        boolean isPrivate,
        AIMerParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public AIMerParameters getParameters()
    {
        return params;
    }
}

