package org.bouncycastle.tls.crypto.impl;

public final class GcmTls12NonceGeneratorUtil
{
    private static volatile AEADNonceGeneratorFactory globalFactory = null;

    public static void setGcmTlsNonceGeneratorFactory(AEADNonceGeneratorFactory factory)
    {
        globalFactory = factory;
    }

    public static boolean isGcmFipsNonceGeneratorFactorySet()
    {
        return globalFactory != null;
    }

    public static AEADNonceGenerator createGcmFipsNonceGenerator(byte[] baseNonce, int counterSizeInBits)
    {
        return globalFactory == null ? null : globalFactory.create(baseNonce, counterSizeInBits);
    }
}
