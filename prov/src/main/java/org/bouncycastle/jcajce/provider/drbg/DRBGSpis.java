package org.bouncycastle.jcajce.provider.drbg;

/**
 * Multi-release hook naming the SecureRandom SPI classes DRBG.Mappings registers. This base copy
 * names the plain DRBG SPIs; the jdk1.9 twin names ParameterisedDRBG, whose SPIs also take
 * java.security.DrbgParameters. Keep the method set of the two copies identical. These are methods
 * rather than constants so the name is resolved against whichever copy the JDK loads.
 */
final class DRBGSpis
{
    private DRBGSpis()
    {
    }

    static String defaultSpi()
    {
        return DRBG.class.getName() + "$Default";
    }

    static String nonceAndIVSpi()
    {
        return DRBG.class.getName() + "$NonceAndIV";
    }
}
