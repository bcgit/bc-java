package org.bouncycastle.pqc.crypto.lms;

public class LMSParameters
{
    private final LMSigParameters lmsParam;
    private final LMOtsParameters lmOTSParam;

    public LMSParameters(LMSigParameters lmsParam, LMOtsParameters lmOTSParam)
    {
        this.lmsParam = lmsParam;
        this.lmOTSParam = lmOTSParam;
    }

    public LMSigParameters getLmsParam()
    {
        return lmsParam;
    }

    public LMOtsParameters getLmOTSParam()
    {
        return lmOTSParam;
    }
}
