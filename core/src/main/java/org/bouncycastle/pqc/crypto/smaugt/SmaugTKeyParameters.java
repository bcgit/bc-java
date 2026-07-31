package org.bouncycastle.pqc.crypto.smaugt;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Common base for SMAUG-T public and private key parameter classes; carries
 * the {@link SmaugTParameters} parameter set the key belongs to.
 */
public class SmaugTKeyParameters
    extends AsymmetricKeyParameter
{
    private final SmaugTParameters params;

    public SmaugTKeyParameters(boolean isPrivate, SmaugTParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public SmaugTParameters getParameters()
    {
        return params;
    }
}
