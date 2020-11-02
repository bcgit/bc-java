package org.bouncycastle.jsse.provider.test;

import java.io.IOException;
import java.net.SocketException;
import java.security.GeneralSecurityException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import junit.framework.TestCase;

public class SSLSocketTest
    extends TestCase
{
    protected void setUp()
    {
        ProviderUtils.setupHighPriority(false);
    }

    public void test_getChannel() throws Exception
    {
        SSLSocket sslSocket = createSSLSocketDisconnected();

        assertNull(sslSocket.getChannel());

        sslSocket.close();
    }

    public void test_getOOBInline() throws Exception
    {
        SSLSocket sslSocket = createSSLSocketDisconnected();

        boolean correctException = false;
        try
        {
            sslSocket.getOOBInline();
        }
        catch (SocketException e)
        {
            correctException = true;
        }

        assertTrue(correctException);

        sslSocket.close();
    }

    public void test_sendUrgentData() throws Exception
    {
        for (int i = 0; i < 10; ++i)
        {
            impl_sendUrgentData(TestUtils.RANDOM.nextInt(256));
        }
    }

    public void test_setOOBInline() throws Exception
    {
        impl_setOOBInline(false);
        impl_setOOBInline(true);
    }

    private static SSLSocket createSSLSocketDisconnected() throws GeneralSecurityException, IOException
    {
        return (SSLSocket)getSSLContextDefault().getSocketFactory().createSocket();
    }

    private static SSLContext getSSLContextDefault() throws GeneralSecurityException
    {
        return SSLContext.getInstance("Default", BouncyCastleJsseProvider.PROVIDER_NAME);
    }

    private static void impl_sendUrgentData(int data) throws Exception
    {
        SSLSocket sslSocket = createSSLSocketDisconnected();

        boolean correctException = false;
        try
        {
            sslSocket.sendUrgentData(data);
        }
        catch (SocketException e)
        {
            correctException = true;
        }

        assertTrue(correctException);

        sslSocket.close();
    }

    private static void impl_setOOBInline(boolean on) throws Exception
    {
        SSLSocket sslSocket = createSSLSocketDisconnected();

        boolean correctException = false;
        try
        {
            sslSocket.setOOBInline(on);
        }
        catch (SocketException e)
        {
            correctException = true;
        }

        assertTrue(correctException);

        sslSocket.close();
    }
}
