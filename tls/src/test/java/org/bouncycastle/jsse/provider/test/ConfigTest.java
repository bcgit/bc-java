package org.bouncycastle.jsse.provider.test;

import java.security.Provider;

import junit.framework.TestCase;

public class ConfigTest
    extends TestCase
{
    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    public void testWithString()
    {
        String BC = ProviderUtils.PROVIDER_NAME_BC;

        Provider jsseProv = ProviderUtils.createProviderBCJSSE("fips:" + BC);

        assertTrue(ProviderUtils.isFipsModeBCJSSE(jsseProv));

        jsseProv = ProviderUtils.createProviderBCJSSE(BC);

        assertFalse(ProviderUtils.isFipsModeBCJSSE(jsseProv));

        jsseProv = ProviderUtils.createProviderBCJSSE("unknown:" + BC);

        assertFalse(ProviderUtils.isFipsModeBCJSSE(jsseProv));
    }

    public void testWithProvider()
    {
        Provider jsseProv = ProviderUtils.createProviderBCJSSE(true, ProviderUtils.createProviderBC());

        assertTrue(ProviderUtils.isFipsModeBCJSSE(jsseProv));

        jsseProv = ProviderUtils.createProviderBCJSSE(ProviderUtils.createProviderBC());

        assertFalse(ProviderUtils.isFipsModeBCJSSE(jsseProv));
    }
}
