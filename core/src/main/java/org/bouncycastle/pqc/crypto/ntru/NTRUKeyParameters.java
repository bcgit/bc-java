package org.bouncycastle.pqc.crypto.ntru;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Abstract class for NTRU key pair.
 */
public abstract class NTRUKeyParameters
    extends AsymmetricKeyParameter
{
    private final NTRUParameters params;

    NTRUKeyParameters(boolean privateKey, NTRUParameters params)
    {
        super(privateKey);
        this.params = params;
    }

    /**
     * Get NTRU parameter set used to generate this key.
     *
     * @return NTRU parameter set used to generate this key
     */
    public NTRUParameters getParameters()
    {
        return params;
    }
}
