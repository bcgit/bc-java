package org.bouncycastle.jsse.provider.test;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import junit.framework.TestCase;

public class SSLServerSocketTest
    extends TestCase
{
    protected void setUp()
    {
        ProviderUtils.setupHighPriority(false);
    }

    public void test_getChannel() throws Exception
    {
        SSLServerSocket sslSocket = createSSLServerSocketDisconnected();

        assertNull(sslSocket.getChannel());

        sslSocket.close();
    }

    private static SSLServerSocket createSSLServerSocketDisconnected() throws GeneralSecurityException, IOException
    {
        return (SSLServerSocket)getSSLContextDefault().getServerSocketFactory().createServerSocket();
    }

    private static SSLContext getSSLContextDefault() throws GeneralSecurityException
    {
        return SSLContext.getInstance("Default", BouncyCastleJsseProvider.PROVIDER_NAME);
    }
}
