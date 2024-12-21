package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.crypto.TlsNonceGenerator;

final public class GcmTls12NonceGeneratorUtil
{
    private static TlsNonceGeneratorFactory tlsNonceGeneratorFactory = null;

    public static void setGcmTlsNonceGeneratorFactory(final TlsNonceGeneratorFactory factory)
    {
        tlsNonceGeneratorFactory = factory;
    }

    public static boolean isGcmFipsNonceGeneratorFactorySet()
    {
        return tlsNonceGeneratorFactory != null;
    }

    public static TlsNonceGenerator createGcmFipsNonceGenerator(final byte[] baseNonce, final int counterSizeInBits)
    {
        return tlsNonceGeneratorFactory != null
                ? tlsNonceGeneratorFactory.create(baseNonce, counterSizeInBits)
                : null;
    }
}
