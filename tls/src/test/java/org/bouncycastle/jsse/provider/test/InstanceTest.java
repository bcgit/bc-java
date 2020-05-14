package org.bouncycastle.jsse.provider.test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import junit.framework.TestCase;

public class InstanceTest
    extends TestCase
{
    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    public void testKeyManager()
        throws Exception
    {
        KeyManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);
    }

    public void testTrustManager()
        throws Exception
    {
        TrustManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);
    }

    public void testSSLContext()
        throws Exception
    {
        SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
    }
}
