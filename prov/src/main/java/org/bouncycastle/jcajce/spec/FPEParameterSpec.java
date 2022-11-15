package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.util.RadixConverter;
import org.bouncycastle.util.Arrays;

public class FPEParameterSpec
    implements AlgorithmParameterSpec
{
    private final RadixConverter radixConverter;
    private final byte[] tweak;
    private final boolean useInverse;

    public FPEParameterSpec(int radix, byte[] tweak)
    {
        this(radix, tweak, false);
    }

    public FPEParameterSpec(int radix, byte[] tweak, boolean useInverse)
    {
        this(new RadixConverter(radix), tweak, useInverse);
    }

    public FPEParameterSpec(RadixConverter radixConverter, byte[] tweak, boolean useInverse)
    {
        this.radixConverter = radixConverter;
        this.tweak = Arrays.clone(tweak);
        this.useInverse = useInverse;
    }

    public int getRadix()
    {
        return radixConverter.getRadix();
    }

    public RadixConverter getRadixConverter()
    {
        return radixConverter;
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
