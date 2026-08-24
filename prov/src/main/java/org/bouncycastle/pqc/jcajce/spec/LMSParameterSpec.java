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
     * Base constructor taking the deprecated org.bouncycastle.pqc.crypto.lms parameter types.
     *
     * @param lmSigParams  the LMS system signature parameters to use.
     * @param lmOtsParameters the LM OTS parameters to use for the underlying one-time signature keys.
     * @deprecated use the constructor taking the org.bouncycastle.crypto.params types.
     */
    @Deprecated
    public LMSParameterSpec(org.bouncycastle.pqc.crypto.lms.LMSigParameters lmSigParams, org.bouncycastle.pqc.crypto.lms.LMOtsParameters lmOtsParameters)
    {
        this(LMSigParameters.getParametersForType(lmSigParams.getType()),
            LMOtsParameters.getParametersForType(lmOtsParameters.getType()));
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
     * Return the LMS system signature parameters as the deprecated
     * org.bouncycastle.pqc.crypto.lms type.
     *
     * @return the LMS system signature parameters.
     * @deprecated use getLMSigParameters().
     */
    @Deprecated
    public org.bouncycastle.pqc.crypto.lms.LMSigParameters getSigParams()
    {
        return org.bouncycastle.pqc.crypto.lms.LMSigParameters.getParametersForType(lmSigParams.getType());
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

    /**
     * Return the LM OTS parameters as the deprecated org.bouncycastle.pqc.crypto.lms type.
     *
     * @return the LM OTS parameters.
     * @deprecated use getLMOtsParameters().
     */
    @Deprecated
    public org.bouncycastle.pqc.crypto.lms.LMOtsParameters getOtsParams()
    {
        return org.bouncycastle.pqc.crypto.lms.LMOtsParameters.getParametersForType(lmOtsParameters.getType());
    }
}
