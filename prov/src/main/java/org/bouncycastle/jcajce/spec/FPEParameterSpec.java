package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

public class FPEParameterSpec
    implements AlgorithmParameterSpec
{
    private final int radix;
    private final byte[] tweak;
    private final boolean useInverse;

    public FPEParameterSpec(int radix, byte[] tweak)
    {
        this(radix, tweak, false);
    }

    public FPEParameterSpec(int radix, byte[] tweak, boolean useInverse)
    {
        this.radix = radix;
        this.tweak = Arrays.clone(tweak);
        this.useInverse = useInverse;
    }

    public int getRadix()
    {
        return radix;
    }

    public byte[] getTweak()
    {
        return Arrays.clone(tweak);
    }

    public boolean isUsingInverseFunction()
    {
        return useInverse;
    }
}
