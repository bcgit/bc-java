package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSigParameters;

/**
 * ParameterSpec for the Leighton-Micali Hash-Based Signature (LMS) scheme.
 * @deprecated use LMSKeyGenParameterSpec
 */
public class LMSParameterSpec
    implements AlgorithmParameterSpec
{
    private final LMSigParameters lmSigParams;
    private final LMOtsParameters lmOtsParameters;

    /**
     * Base constructor.
     *
     * @param lmSigParams  the LMS system signature parameters to use.
     * @param lmOtsParameters the LM OTS parameters to use for the underlying one-time signature keys.
     */
    public LMSParameterSpec(LMSigParameters lmSigParams, LMOtsParameters lmOtsParameters)
    {
        this.lmSigParams = lmSigParams;
        this.lmOtsParameters = lmOtsParameters;
    }

    /**
     * Return the LMS system signature parameters.
     *
     * @return the LMS system signature parameters.
     */
    public LMSigParameters getLMSigParameters()
    {
        return lmSigParams;
    }

    /**
     * Return the LM OTS parameters to use for the underlying one-time signature keys.
     * 
     * @return the LM OTS parameters.
     */
    public LMOtsParameters getLMOtsParameters()
    {
        return lmOtsParameters;
    }
}
