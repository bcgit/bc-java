package org.bouncycastle.jsse.provider.test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import junit.framework.TestCase;

public class InstanceTest
    extends TestCase
{
    protected void setUp()
    {
        TestUtils.setupProvidersLowPriority();
    }

    public void testKeyManager()
        throws Exception
    {
        KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
    }

    public void testTrustManager()
        throws Exception
    {
        TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
    }

    public void testSSLContext()
        throws Exception
    {
        SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
    }
}
