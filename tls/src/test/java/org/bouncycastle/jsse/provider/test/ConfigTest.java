package org.bouncycastle.jsse.provider.test;


import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class ConfigTest
    extends TestCase
{
    protected void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testWithString()
    {
        String BC = BouncyCastleProvider.PROVIDER_NAME;

        BouncyCastleJsseProvider jsseProv = new BouncyCastleJsseProvider("fips:" + BC);

        assertTrue(jsseProv.isFipsMode());

        jsseProv = new BouncyCastleJsseProvider(BC);

        assertFalse(jsseProv.isFipsMode());

        jsseProv = new BouncyCastleJsseProvider("unknown:" + BC);

        assertFalse(jsseProv.isFipsMode());
    }

    public void testWithProvider()
    {
        BouncyCastleJsseProvider jsseProv = new BouncyCastleJsseProvider(true, new BouncyCastleProvider());

        assertTrue(jsseProv.isFipsMode());

        jsseProv = new BouncyCastleJsseProvider(new BouncyCastleProvider());

        assertFalse(jsseProv.isFipsMode());
    }
}
