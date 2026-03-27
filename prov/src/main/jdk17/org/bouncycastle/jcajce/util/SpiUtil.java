package org.bouncycastle.jcajce.util;

public abstract class SpiUtil
{
    public static boolean hasKDF()
    {
        return false;
    }

    public static boolean hasKEM()
    {
        // TODO Dynamic check for javax.crypto.KEMSpi (added in 21 and backported to 17 MR 1)
        return true;
    }
}
