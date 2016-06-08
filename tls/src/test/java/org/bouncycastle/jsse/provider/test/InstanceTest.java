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

    protected void tearDown()
    {
        Security.removeProvider("BCTLS");
    }

    public void testKeyManager()
        throws Exception
    {
        KeyManagerFactory.getInstance("PKIX", "BCTLS");
    }

    public void testTrustManager()
        throws Exception
    {
        TrustManagerFactory.getInstance("PKIX", "BCTLS");
    }

    public void testSSLContext()
        throws Exception
    {
        SSLContext.getInstance("TLS", "BCTLS");
    }
}
