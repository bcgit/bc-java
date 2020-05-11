package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;

/**
 * ParameterSpec for the Leighton-Micali Hash-Based Signature (LMS) scheme.
 */
public class LMSKeyGenParameterSpec
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
    public LMSKeyGenParameterSpec(LMSigParameters lmSigParams, LMOtsParameters lmOtsParameters)
    {
        this.lmSigParams = lmSigParams;
        this.lmOtsParameters = lmOtsParameters;
    }

    /**
     * Return the LMS system signature parameters.
     *
     * @return the LMS system signature parameters.
     */
    public LMSigParameters getSigParams()
    {
        return lmSigParams;
    }

    /**
     * Return the LM OTS parameters to use for the underlying one-time signature keys.
     * 
     * @return the LM OTS parameters.
     */
    public LMOtsParameters getOtsParams()
    {
        return lmOtsParameters;
    }
}
