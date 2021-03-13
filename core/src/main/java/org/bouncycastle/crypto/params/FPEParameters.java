package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.Arrays;

public final class FPEParameters
    implements CipherParameters
{
    private final KeyParameter key;
    private final int radix;
    private final byte[] tweak;
    private final boolean useInverse;

    public FPEParameters(KeyParameter key, int radix, byte[] tweak)
    {
        this(key, radix, tweak, false);
    }

    public FPEParameters(KeyParameter key, int radix, byte[] tweak, boolean useInverse)
    {
        this.key = key;
        this.radix = radix;
        this.tweak = Arrays.clone(tweak);
        this.useInverse = useInverse;
    }

    public KeyParameter getKey()
    {
        return key;
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