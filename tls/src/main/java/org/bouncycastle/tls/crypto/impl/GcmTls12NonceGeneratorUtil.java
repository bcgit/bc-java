package org.bouncycastle.tls.crypto.impl;

import java.security.AccessController;
import java.security.PrivilegedAction;

final public class GcmTls12NonceGeneratorUtil
{
    private static AEADNonceGeneratorFactory tlsNonceGeneratorFactory = null;

    public static void setGcmTlsNonceGeneratorFactory(final AEADNonceGeneratorFactory factory)
    {
        tlsNonceGeneratorFactory = factory;
    }

    public static boolean isGcmFipsNonceGeneratorFactorySet()
    {
        return tlsNonceGeneratorFactory != null;
    }

    public static AEADNonceGenerator createGcmFipsNonceGenerator(final byte[] baseNonce, final int counterSizeInBits)
    {
        return tlsNonceGeneratorFactory != null
                ? tlsNonceGeneratorFactory.create(baseNonce, counterSizeInBits)
                : null;
    }
}
