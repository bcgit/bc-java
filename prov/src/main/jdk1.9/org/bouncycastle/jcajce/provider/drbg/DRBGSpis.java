package org.bouncycastle.jcajce.provider.drbg;

/**
 * Multi-release hook naming the SecureRandom SPI classes DRBG.Mappings registers. This jdk1.9 copy
 * names ParameterisedDRBG, whose SPIs also take java.security.DrbgParameters; the base copy names
 * the plain DRBG SPIs. Keep the method set of the two copies identical. These are methods rather
 * than constants so the name is resolved against whichever copy the JDK loads.
 */
final class DRBGSpis
{
    private DRBGSpis()
    {
    }

    static String defaultSpi()
    {
        return ParameterisedDRBG.class.getName() + "$Default";
    }

    static String nonceAndIVSpi()
    {
        return ParameterisedDRBG.class.getName() + "$NonceAndIV";
    }
}
