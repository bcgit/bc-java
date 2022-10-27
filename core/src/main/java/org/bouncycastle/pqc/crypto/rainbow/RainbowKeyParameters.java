package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class RainbowKeyParameters
    extends AsymmetricKeyParameter
{
    private final RainbowParameters params;
    private final int docLength;

    public RainbowKeyParameters(boolean isPrivateKey, RainbowParameters params)
    {
        super(isPrivateKey);
        this.params = params;
        this.docLength = params.getM();
    }

    public RainbowParameters getParameters()
    {
        return params;
    }

    /**
     * @return the docLength
     */
    public int getDocLength()
    {
        return this.docLength;
    }
}
