package org.bouncycastle.jsse.provider.test;

import java.security.Security;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import junit.framework.TestCase;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class InstanceTest
    extends TestCase
{
    protected void setUp()
    {
        Security.addProvider(new BouncyCastleJsseProvider());
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
