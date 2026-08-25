package org.bouncycastle.crypto.params;

public class LMSParameters
{
    private final LMSigParameters lmSigParam;
    private final LMOtsParameters lmOTSParam;

    public LMSParameters(LMSigParameters lmSigParam, LMOtsParameters lmOTSParam)
    {
        this.lmSigParam = lmSigParam;
        this.lmOTSParam = lmOTSParam;
    }

    public LMSigParameters getLMSigParam()
    {
        return lmSigParam;
    }

    public LMOtsParameters getLMOTSParam()
    {
        return lmOTSParam;
    }

    /**
     * The strength a key generator reports for this parameter set: the total number of
     * message bytes' worth of one-time keys the tree carries (2^h keys of m bytes).
     */
    static int calculateStrength(LMSParameters lmsParameters)
    {
        if (lmsParameters == null)
        {
            throw new NullPointerException("lmsParameters cannot be null");
        }

        LMSigParameters sigParameters = lmsParameters.getLMSigParam();
        return (1 << sigParameters.getH()) * sigParameters.getM();
    }
}
