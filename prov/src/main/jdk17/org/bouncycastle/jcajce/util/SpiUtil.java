package org.bouncycastle.jcajce.util;

import org.bouncycastle.jcajce.provider.symmetric.util.ClassUtil;

public abstract class SpiUtil
{
    // In case of unexpected failure, defaulting to true seems the least bad choice
    private static final boolean HAS_KEM = isClassPresent("javax.crypto.KEMSpi", true);

    public static boolean hasKDF()
    {
        return false;
    }

    public static boolean hasKEM()
    {
        return HAS_KEM;
    }

    private static boolean isClassPresent(String className, boolean defaultResult)
    {
        try
        {
            return ClassUtil.loadClass(SpiUtil.class, "javax.crypto.KEMSpi") != null;
        }
        catch (Exception e)
        {
            return defaultResult;
        }
    }
}
