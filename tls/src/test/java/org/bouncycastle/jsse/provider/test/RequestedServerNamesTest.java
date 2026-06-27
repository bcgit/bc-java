package org.bouncycastle.jsse.provider.test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import junit.framework.TestCase;

/**
 * Regression test for github #1773: ExtendedSSLSession.getRequestedServerNames() threw
 * UnsupportedOperationException on the established BCJSSE session (it only worked on the
 * transient handshake session), so a server could not read the SNI the client requested after
 * the handshake completed.
 */
public class RequestedServerNamesTest
    extends TestCase
{
    private static final String HOST = "localhost";
    private static final String SNI_HOST = "test.bouncycastle.org";

    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    static class Client
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final String protocol;
        private final KeyStore trustStore;
        private final CountDownLatch latch;

        Client(int port, String protocol, X509Certificate trustAnchor)
            throws GeneralSecurityException, IOException
        {
            KeyStore trustStore = createKeyStore();
            trustStore.setCertificateEntry("server", trustAnchor);

            this.port = port;
            this.protocol = protocol;
            this.trustStore = trustStore;
            this.latch = new CountDownLatch(1);
        }

        public Exception call() throws Exception
        {
            try
            {
                TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX",
                    ProviderUtils.PROVIDER_NAME_BCJSSE);
                trustMgrFact.init(trustStore);

                SSLContext clientContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
                clientContext.init(null, trustMgrFact.getTrustManagers(),
                    SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

                SSLSocketFactory fact = clientContext.getSocketFactory();
                SSLSocket cSock = (SSLSocket)fact.createSocket(HOST, port);
                cSock.setEnabledProtocols(new String[]{ protocol });

                SSLParameters sslParameters = cSock.getSSLParameters();
                sslParameters.setServerNames(
                    Collections.<SNIServerName>singletonList(new SNIHostName(SNI_HOST)));
                cSock.setSSLParameters(sslParameters);

                TestProtocolUtil.doClientProtocol(cSock, "Hello");
            }
            finally
            {
                latch.countDown();
            }

            return null;
        }

        public void await() throws InterruptedException
        {
            latch.await();
        }
    }

    static class Server
        implements TestProtocolUtil.BlockingCallable
    {
        private final String protocol;
        private final SSLServerSocket sSock;
        private final CountDownLatch latch;

        Server(int port, String protocol, KeyStore serverStore, char[] keyPass)
            throws GeneralSecurityException, IOException
        {
            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX",
                ProviderUtils.PROVIDER_NAME_BCJSSE);
            keyMgrFact.init(serverStore, keyPass);

            SSLContext serverContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
            serverContext.init(keyMgrFact.getKeyManagers(), null,
                SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

            SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
            this.sSock = (SSLServerSocket)fact.createServerSocket(port);

            SSLUtils.enableAll(sSock);

            this.protocol = protocol;
            this.latch = new CountDownLatch(1);
        }

        int getPort()
        {
            return sSock.getLocalPort();
        }

        public Exception call() throws Exception
        {
            try
            {
                latch.countDown();

                SSLSocket sslSock = (SSLSocket)sSock.accept();
                sslSock.setEnabledProtocols(new String[]{ protocol });

                SSLSession session = sslSock.getSession();
                assertNotNull(session);
                assertFalse("SSL_NULL_WITH_NULL_NULL".equals(session.getCipherSuite()));

                // github #1773: this must not throw, and must report the SNI the client sent.
                assertTrue("session is not an ExtendedSSLSession", session instanceof ExtendedSSLSession);
                List<SNIServerName> requested = ((ExtendedSSLSession)session).getRequestedServerNames();
                assertNotNull(requested);
                assertEquals(1, requested.size());
                SNIServerName name = requested.get(0);
                assertTrue(name instanceof SNIHostName);
                assertEquals(SNI_HOST, ((SNIHostName)name).getAsciiName());

                TestProtocolUtil.doServerProtocol(sslSock, "World");

                sslSock.close();
                sSock.close();
            }
            finally
            {
                latch.countDown();
            }

            return null;
        }

        public void await() throws InterruptedException
        {
            latch.await();
        }
    }

    public void test12() throws Exception
    {
        implTest("TLSv1.2");
    }

    public void test13() throws Exception
    {
        implTest("TLSv1.3");
    }

    private void implTest(String protocol) throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        KeyPair caKeyPair = TestUtils.generateRSAKeyPair();
        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore serverKs = createKeyStore();
        serverKs.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        Server server = new Server(0, protocol, serverKs, keyPass);
        TestProtocolUtil.runClientAndServer(server,
            new Client(server.getPort(), protocol, caCert));
    }

    private static KeyStore createKeyStore() throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        return keyStore;
    }
}
