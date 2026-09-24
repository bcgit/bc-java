package org.bouncycastle.jsse.provider.test;

import java.security.Security;
import java.util.Arrays;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCSSLContext;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLServerSocket;
import org.bouncycastle.jsse.BCSSLSessionContext;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jsse.util.ContextUtil;

import junit.framework.TestCase;

/**
 * Tests for {@link BCSSLContext} as obtained via {@link ContextUtil#getBCSSLContext(SSLContext)}.
 * <p>
 * The context is initialised with <code>jdk.tls.server.protocols</code> restricted to TLSv1.2, so that its
 * client and server defaults differ and the choice between them is observable.
 * </p>
 */
public class DefaultParametersTest
    extends TestCase
{
    private static final String PROPERTY_SERVER_PROTOCOLS = "jdk.tls.server.protocols";
    private static final String[] SERVER_PROTOCOLS = new String[]{ "TLSv1.2" };

    private SSLContext sslContext;

    protected void setUp() throws Exception
    {
        ProviderUtils.setupHighPriority(false);

        String previous = System.getProperty(PROPERTY_SERVER_PROTOCOLS);
        System.setProperty(PROPERTY_SERVER_PROTOCOLS, SERVER_PROTOCOLS[0]);
        try
        {
            sslContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
            sslContext.init(null, null, null);
        }
        finally
        {
            if (previous == null)
            {
                System.getProperties().remove(PROPERTY_SERVER_PROTOCOLS);
            }
            else
            {
                System.setProperty(PROPERTY_SERVER_PROTOCOLS, previous);
            }
        }
    }

    public void test_contextDefaults() throws Exception
    {
        BCSSLContext bcContext = ContextUtil.getBCSSLContext(sslContext);
        assertNotNull(bcContext);

        assertParametersEqual(getClientDefaults(), bcContext.getDefaultParameters(true));
        assertParametersEqual(getServerDefaults(), bcContext.getDefaultParameters(false));

        SSLParameters supported = sslContext.getSupportedSSLParameters();
        for (int i = 0; i < 2; ++i)
        {
            BCSSLParameters bcSupported = bcContext.getSupportedParameters(i == 0);
            assertTrue(Arrays.equals(supported.getCipherSuites(), bcSupported.getCipherSuites()));
            assertTrue(Arrays.equals(supported.getProtocols(), bcSupported.getProtocols()));
        }

        // Both session contexts belong to the same initialization
        SSLSessionContext serverSessionContext = sslContext.getServerSessionContext();
        assertTrue(serverSessionContext instanceof BCSSLSessionContext);
        assertSame(bcContext, ((BCSSLSessionContext)serverSessionContext).getBCSSLContext());
    }

    public void test_contextDefaultsAreCopies() throws Exception
    {
        BCSSLContext bcContext = ContextUtil.getBCSSLContext(sslContext);

        BCSSLParameters defaults = bcContext.getDefaultParameters(true);
        defaults.setProtocols(SERVER_PROTOCOLS);
        defaults.setNamedGroups(new String[]{ "x25519" });

        assertParametersEqual(getClientDefaults(), bcContext.getDefaultParameters(true));
    }

    public void test_contextSnapshot() throws Exception
    {
        BCSSLContext before = ContextUtil.getBCSSLContext(sslContext);

        // Re-initialize without the server protocols restriction
        sslContext.init(null, null, null);

        BCSSLContext after = ContextUtil.getBCSSLContext(sslContext);
        assertNotSame(before, after);

        assertTrue(Arrays.equals(SERVER_PROTOCOLS, before.getDefaultParameters(false).getProtocols()));
        assertFalse(Arrays.equals(SERVER_PROTOCOLS, after.getDefaultParameters(false).getProtocols()));
    }

    public void test_contextUninitialized() throws Exception
    {
        SSLContext uninitialized = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
        try
        {
            ContextUtil.getBCSSLContext(uninitialized);
            fail("uninitialized SSLContext accepted");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    public void test_contextNonBC() throws Exception
    {
        if (Security.getProvider("SunJSSE") == null)
        {
            return;
        }

        SSLContext sunContext = SSLContext.getInstance("TLS", "SunJSSE");
        sunContext.init(null, null, null);

        assertNull(ContextUtil.getBCSSLContext(sunContext));
    }

    private BCSSLParameters getClientDefaults() throws Exception
    {
        SSLSocket sslSocket = (SSLSocket)sslContext.getSocketFactory().createSocket();
        try
        {
            BCSSLParameters clientDefaults = ((BCSSLSocket)sslSocket).getParameters();

            // Consistent with the (client-mode) SSLContext defaults, but not restricted like the server's
            assertTrue(Arrays.equals(sslContext.getDefaultSSLParameters().getCipherSuites(),
                clientDefaults.getCipherSuites()));
            assertTrue(Arrays.equals(sslContext.getDefaultSSLParameters().getProtocols(),
                clientDefaults.getProtocols()));
            assertFalse(Arrays.equals(SERVER_PROTOCOLS, clientDefaults.getProtocols()));

            return clientDefaults;
        }
        finally
        {
            sslSocket.close();
        }
    }

    private BCSSLParameters getServerDefaults() throws Exception
    {
        SSLServerSocket sslServerSocket = (SSLServerSocket)sslContext.getServerSocketFactory().createServerSocket();
        try
        {
            BCSSLParameters serverDefaults = ((BCSSLServerSocket)sslServerSocket).getParameters();

            assertTrue(Arrays.equals(SERVER_PROTOCOLS, serverDefaults.getProtocols()));

            return serverDefaults;
        }
        finally
        {
            sslServerSocket.close();
        }
    }

    private static void assertParametersEqual(BCSSLParameters expected, BCSSLParameters actual)
    {
        assertTrue(Arrays.equals(expected.getCipherSuites(), actual.getCipherSuites()));
        assertTrue(Arrays.equals(expected.getProtocols(), actual.getProtocols()));
        assertEquals(expected.getNeedClientAuth(), actual.getNeedClientAuth());
        assertEquals(expected.getWantClientAuth(), actual.getWantClientAuth());
        assertEquals(expected.getEndpointIdentificationAlgorithm(), actual.getEndpointIdentificationAlgorithm());
        assertEquals(expected.getUseCipherSuitesOrder(), actual.getUseCipherSuitesOrder());
        assertEquals(expected.getUseNamedGroupsOrder(), actual.getUseNamedGroupsOrder());
        assertEquals(expected.getEnableRetransmissions(), actual.getEnableRetransmissions());
        assertEquals(expected.getMaximumPacketSize(), actual.getMaximumPacketSize());
        assertTrue(Arrays.equals(expected.getApplicationProtocols(), actual.getApplicationProtocols()));
        assertTrue(Arrays.equals(expected.getSignatureSchemes(), actual.getSignatureSchemes()));
        assertTrue(Arrays.equals(expected.getSignatureSchemesCert(), actual.getSignatureSchemesCert()));
        assertTrue(Arrays.equals(expected.getNamedGroups(), actual.getNamedGroups()));
        assertTrue(Arrays.equals(expected.getEarlyKeyShares(), actual.getEarlyKeyShares()));
    }
}
