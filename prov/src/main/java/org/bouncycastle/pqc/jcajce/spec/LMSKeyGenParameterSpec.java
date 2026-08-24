package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSigParameters;

/**
 * ParameterSpec for the Leighton-Micali Hash-Based Signature (LMS) scheme.
 */
public class LMSKeyGenParameterSpec
    implements AlgorithmParameterSpec
{
    private static final Map<String, LMSigParameters> sigParameters = new HashMap<String, LMSigParameters>();
    private static final Map<String, LMOtsParameters> otsParameters = new HashMap<String, LMOtsParameters>();

    static
    {
        sigParameters.put("lms-sha256-n32-h5", LMSigParameters.lms_sha256_n32_h5);
        sigParameters.put("lms-sha256-n32-h10", LMSigParameters.lms_sha256_n32_h10);
        sigParameters.put("lms-sha256-n32-h15", LMSigParameters.lms_sha256_n32_h15);
        sigParameters.put("lms-sha256-n32-h20", LMSigParameters.lms_sha256_n32_h20);
        sigParameters.put("lms-sha256-n32-h25", LMSigParameters.lms_sha256_n32_h25);
        sigParameters.put("lms-sha256-n24-h5", LMSigParameters.lms_sha256_n24_h5);
        sigParameters.put("lms-sha256-n24-h10", LMSigParameters.lms_sha256_n24_h10);
        sigParameters.put("lms-sha256-n24-h15", LMSigParameters.lms_sha256_n24_h15);
        sigParameters.put("lms-sha256-n24-h20", LMSigParameters.lms_sha256_n24_h20);
        sigParameters.put("lms-sha256-n24-h25", LMSigParameters.lms_sha256_n24_h25);
        sigParameters.put("lms-shake256-n32-h5", LMSigParameters.lms_shake256_n32_h5);
        sigParameters.put("lms-shake256-n32-h10", LMSigParameters.lms_shake256_n32_h10);
        sigParameters.put("lms-shake256-n32-h15", LMSigParameters.lms_shake256_n32_h15);
        sigParameters.put("lms-shake256-n32-h20", LMSigParameters.lms_shake256_n32_h20);
        sigParameters.put("lms-shake256-n32-h25", LMSigParameters.lms_shake256_n32_h25);
        sigParameters.put("lms-shake256-n24-h5", LMSigParameters.lms_shake256_n24_h5);
        sigParameters.put("lms-shake256-n24-h10", LMSigParameters.lms_shake256_n24_h10);
        sigParameters.put("lms-shake256-n24-h15", LMSigParameters.lms_shake256_n24_h15);
        sigParameters.put("lms-shake256-n24-h20", LMSigParameters.lms_shake256_n24_h20);
        sigParameters.put("lms-shake256-n24-h25", LMSigParameters.lms_shake256_n24_h25);
        
        otsParameters.put("sha256-n32-w1", LMOtsParameters.sha256_n32_w1);
        otsParameters.put("sha256-n32-w2", LMOtsParameters.sha256_n32_w2);
        otsParameters.put("sha256-n32-w4", LMOtsParameters.sha256_n32_w4);
        otsParameters.put("sha256-n32-w8", LMOtsParameters.sha256_n32_w8);
    }

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
     * Base constructor taking the deprecated org.bouncycastle.pqc.crypto.lms parameter types.
     *
     * @param lmSigParams  the LMS system signature parameters to use.
     * @param lmOtsParameters the LM OTS parameters to use for the underlying one-time signature keys.
     * @deprecated use the constructor taking the org.bouncycastle.crypto.params types.
     */
    @Deprecated
    public LMSKeyGenParameterSpec(org.bouncycastle.pqc.crypto.lms.LMSigParameters lmSigParams, org.bouncycastle.pqc.crypto.lms.LMOtsParameters lmOtsParameters)
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

    public static LMSKeyGenParameterSpec fromNames(String sigParams, String otsParams)
    {
        if (!sigParameters.containsKey(sigParams))
        {
            throw new IllegalArgumentException("LM signature parameter name " + sigParams + " not recognized");
        }
        if (!otsParameters.containsKey(otsParams))
        {
            throw new IllegalArgumentException("LM OTS parameter name " + otsParams + " not recognized");
        }
        
        return new LMSKeyGenParameterSpec(sigParameters.get(sigParams), otsParameters.get(otsParams));
    }
}
