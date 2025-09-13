package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Parameters for the CompositeSignature algorithm.
 */
public class CompositeSignatureSpec
    implements AlgorithmParameterSpec
{
    private final boolean isPrehashMode;
    private final AlgorithmParameterSpec secondaryParameterSpec;

    /**
     * Base Constructor.
     *
     * @param isPrehashMode if true, msg passed in will be the precalculated pre-hash.
     */
    public CompositeSignatureSpec(boolean isPrehashMode)
    {
        this(isPrehashMode, null);
    }

    /**
     * Constructor which allows for another parameter spec (usually ContextParameterSpec).
     *
     * @param isPrehashMode if true, msg passed in will be the precalculated pre-hash.
     * @param secondaryParameterSpec the other spec, in addition to pre-hash mode, which needs to be applied.
     */
    public CompositeSignatureSpec(boolean isPrehashMode, AlgorithmParameterSpec secondaryParameterSpec)
    {
        this.isPrehashMode = isPrehashMode;
        this.secondaryParameterSpec = secondaryParameterSpec;
    }

    public boolean isPrehashMode()
    {
        return isPrehashMode;
    }

    public AlgorithmParameterSpec getSecondarySpec()
    {
        return secondaryParameterSpec;
    }
}
