package org.bouncycastle.jsse.provider.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import junit.framework.TestCase;

public class ConfigTest
    extends TestCase
{
    protected void setUp()
    {
        TestUtils.setupProvidersLowPriority();
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
