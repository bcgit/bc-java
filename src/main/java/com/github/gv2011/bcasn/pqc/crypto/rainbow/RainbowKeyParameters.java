package com.github.gv2011.bcasn.pqc.crypto.rainbow;

import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;

public class RainbowKeyParameters 
    extends AsymmetricKeyParameter
{
    private int docLength;

    public RainbowKeyParameters(
            boolean         isPrivate,
            int             docLength)
    {
        super(isPrivate);
        this.docLength = docLength;
    }

    /**
     * @return the docLength
     */
    public int getDocLength()
    {
        return this.docLength;
    }
}
