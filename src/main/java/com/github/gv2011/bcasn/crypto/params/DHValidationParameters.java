package com.github.gv2011.bcasn.crypto.params;

import com.github.gv2011.bcasn.util.Arrays;

public class DHValidationParameters
{
    private byte[]  seed;
    private int     counter;

    public DHValidationParameters(
        byte[]  seed,
        int     counter)
    {
        this.seed = seed;
        this.counter = counter;
    }

    public int getCounter()
    {
        return counter;
    }

    public byte[] getSeed()
    {
        return seed;
    }

    public boolean equals(
        Object o)
    {
        if (!(o instanceof DHValidationParameters))
        {
            return false;
        }

        DHValidationParameters  other = (DHValidationParameters)o;

        if (other.counter != this.counter)
        {
            return false;
        }

        return Arrays.areEqual(this.seed, other.seed);
    }

    public int hashCode()
    {
        return counter ^ Arrays.hashCode(seed);
    }
}
