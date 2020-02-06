package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;

public class LMSParameterSpec
    implements AlgorithmParameterSpec
{
    private final LMSigParameters lmSigParams;
    private final LMOtsParameters lmOtsParameters;

    public LMSParameterSpec(LMSigParameters lmSigParams, LMOtsParameters lmOtsParameters)
    {
        this.lmSigParams = lmSigParams;
        this.lmOtsParameters = lmOtsParameters;
    }

    public LMSigParameters getSigParams()
    {
        return lmSigParams;
    }

    public LMOtsParameters getOtsParams()
    {
        return lmOtsParameters;
    }
}
