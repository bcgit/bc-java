package org.bouncycastle.jcajce.util;

public abstract class SpiUtil
{
    public static boolean hasKDF()
    {
        return true;
    }

    public static boolean hasKEM()
    {
        return true;
    }
}
