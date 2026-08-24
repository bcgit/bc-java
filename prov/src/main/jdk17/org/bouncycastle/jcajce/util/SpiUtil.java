package org.bouncycastle.jcajce.util;

import org.bouncycastle.jcajce.provider.symmetric.util.ClassUtil;

/**
 * Reports which JDK SPI families the runtime provides, so the registration classes in the base tree
 * can skip a service the runtime cannot support. One copy per relevant JDK - the base tree answers
 * no to everything, this jdk17 copy detects {@code javax.crypto.KEMSpi}, and the jdk25 copy answers
 * yes to both - which is exactly what makes it the wrong place to host anything else: a method
 * added here is absent from the jdk25 copy, and on a JDK 25 runtime that is the copy that loads.
 * Shared helper bodies belong on a class with no versioned twin, such as
 * {@code org.bouncycastle.jcajce.provider.asymmetric.util.KemSpiUtil}.
 */
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
            return ClassUtil.loadClass(SpiUtil.class, className) != null;
        }
        catch (Exception e)
        {
            return defaultResult;
        }
    }
}
