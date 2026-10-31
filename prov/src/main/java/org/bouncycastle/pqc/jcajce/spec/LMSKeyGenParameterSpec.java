package org.bouncycastle.pqc.jcajce.spec;

import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSigParameters;

/**
 * ParameterSpec for the Leighton-Micali Hash-Based Signature (LMS) scheme.
 *
 * @deprecated use {@link org.bouncycastle.jcajce.spec.LMSKeyGenParameterSpec} instead.
 */
@Deprecated
public class LMSKeyGenParameterSpec
    extends org.bouncycastle.jcajce.spec.LMSKeyGenParameterSpec
{
    /**
     * Base constructor.
     *
     * @param lmSigParams  the LMS system signature parameters to use.
     * @param lmOtsParameters the LM OTS parameters to use for the underlying one-time signature keys.
     */
    public LMSKeyGenParameterSpec(LMSigParameters lmSigParams, LMOtsParameters lmOtsParameters)
    {
        super(lmSigParams, lmOtsParameters);
    }

    /**
     * Return the parameter spec for the named LMS signature and LM OTS parameter sets.
     *
     * @param sigParams the name of the LMS system signature parameters, such as "lms-sha256-n32-h5".
     * @param otsParams the name of the LM OTS parameters, such as "sha256-n32-w1".
     * @return the parameter spec naming both.
     */
    public static LMSKeyGenParameterSpec fromNames(String sigParams, String otsParams)
    {
        org.bouncycastle.jcajce.spec.LMSKeyGenParameterSpec spec =
            org.bouncycastle.jcajce.spec.LMSKeyGenParameterSpec.fromNames(sigParams, otsParams);

        return new LMSKeyGenParameterSpec(spec.getLMSigParameters(), spec.getLMOtsParameters());
    }
}
