package org.bouncycastle.jsse.provider.test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLServerSocket;
import org.bouncycastle.jsse.BCSSLSocket;
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

    public void test_getSetParameters() throws Exception
    {
        SSLServerSocket sslSocket = createSSLServerSocketDisconnected();
        try
        {
            assertTrue(sslSocket instanceof BCSSLServerSocket);
            BCSSLServerSocket bcSocket = (BCSSLServerSocket)sslSocket;

            BCSSLParameters params = bcSocket.getParameters();
            assertTrue(Arrays.equals(sslSocket.getEnabledCipherSuites(), params.getCipherSuites()));
            assertTrue(Arrays.equals(sslSocket.getEnabledProtocols(), params.getProtocols()));
            assertFalse(params.getNeedClientAuth());
            assertFalse(params.getWantClientAuth());

            String[] cipherSuites = new String[]{ "TLS_AES_128_GCM_SHA256" };
            String[] protocols = new String[]{ "TLSv1.3" };
            String[] namedGroups = new String[]{ "x25519", "secp256r1" };

            params.setCipherSuites(cipherSuites);
            params.setProtocols(protocols);
            params.setNeedClientAuth(true);
            params.setUseNamedGroupsOrder(true);
            params.setNamedGroups(namedGroups);

            // The returned parameters are a copy; changing them has no effect until set
            assertFalse(bcSocket.getParameters().getNeedClientAuth());

            bcSocket.setParameters(params);

            BCSSLParameters updated = bcSocket.getParameters();
            assertTrue(Arrays.equals(cipherSuites, updated.getCipherSuites()));
            assertTrue(Arrays.equals(protocols, updated.getProtocols()));
            assertTrue(updated.getNeedClientAuth());
            assertTrue(updated.getUseNamedGroupsOrder());
            assertTrue(Arrays.equals(namedGroups, updated.getNamedGroups()));

            // Visible through the standard SSLServerSocket accessors too
            assertTrue(Arrays.equals(cipherSuites, sslSocket.getEnabledCipherSuites()));
            assertTrue(Arrays.equals(protocols, sslSocket.getEnabledProtocols()));
            assertTrue(sslSocket.getNeedClientAuth());

            // Null cipher suites and protocols leave the current settings unchanged, but a null
            // namedGroups is applied, restoring the default
            BCSSLParameters partial = new BCSSLParameters();
            partial.setWantClientAuth(true);
            bcSocket.setParameters(partial);

            assertTrue(Arrays.equals(cipherSuites, sslSocket.getEnabledCipherSuites()));
            assertTrue(Arrays.equals(protocols, sslSocket.getEnabledProtocols()));
            assertFalse(sslSocket.getNeedClientAuth());
            assertTrue(sslSocket.getWantClientAuth());
            assertNull(bcSocket.getParameters().getNamedGroups());

            try
            {
                bcSocket.setParameters(new BCSSLParameters(null, new String[]{ "NoSuchProtocol" }));
                fail("unsupported protocol accepted");
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
            assertTrue(Arrays.equals(protocols, sslSocket.getEnabledProtocols()));
        }
        finally
        {
            sslSocket.close();
        }
    }

    public void test_setParametersAppliesToAcceptedSockets() throws Exception
    {
        SSLServerSocket sslServerSocket = createSSLServerSocketDisconnected();
        try
        {
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            sslServerSocket.bind(new InetSocketAddress(loopback, 0));

            String[] namedGroups = new String[]{ "x25519" };

            BCSSLServerSocket bcServerSocket = (BCSSLServerSocket)sslServerSocket;
            BCSSLParameters params = bcServerSocket.getParameters();
            params.setNamedGroups(namedGroups);
            params.setUseNamedGroupsOrder(true);
            bcServerSocket.setParameters(params);

            // A plain TCP connection is enough; accept() does not start the handshake
            Socket client = new Socket(loopback, sslServerSocket.getLocalPort());
            try
            {
                Socket accepted = sslServerSocket.accept();
                try
                {
                    assertTrue(accepted instanceof BCSSLSocket);
                    BCSSLParameters acceptedParams = ((BCSSLSocket)accepted).getParameters();
                    assertTrue(Arrays.equals(namedGroups, acceptedParams.getNamedGroups()));
                    assertTrue(acceptedParams.getUseNamedGroupsOrder());
                }
                finally
                {
                    accepted.close();
                }
            }
            finally
            {
                client.close();
            }
        }
        finally
        {
            sslServerSocket.close();
        }
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
