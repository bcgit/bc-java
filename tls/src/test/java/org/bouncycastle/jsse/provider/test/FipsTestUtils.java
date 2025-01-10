package org.bouncycastle.jsse.provider.test;

import java.security.Provider;
import java.security.Security;

abstract class FipsTestUtils
{
    static final boolean provAllowGCMCiphersIn12 =
        "true".equalsIgnoreCase(System.getProperty("org.bouncycastle.jsse.fips.allowGCMCiphersIn12"));

    static final boolean provAllowRSAKeyExchange =
        "true".equalsIgnoreCase(System.getProperty("org.bouncycastle.jsse.fips.allowRSAKeyExchange"));

    static void setupFipsSuite()
    {
        if (!provAllowGCMCiphersIn12)
        {
            ProviderUtils.setupHighPriority(true);
            return;
        }

        Provider bc = ProviderUtils.getProviderBC();

        if (bc == null)
        {
            bc = ProviderUtils.createProviderBC();
        }
        else
        {
            ProviderUtils.removeProviderBC();
        }

        ProviderUtils.removeProviderBCJSSE();

        Provider bcjsse = ProviderUtils.createProviderBCJSSE(true, new FipsJcaTlsCryptoProvider().setProvider(bc));

        Security.insertProviderAt(bc, 1);
        Security.insertProviderAt(bcjsse, 2);
    }

    static void teardownFipsSuite()
    {
        if (provAllowGCMCiphersIn12)
        {
            ProviderUtils.removeProviderBCJSSE();
        }
    }
}
