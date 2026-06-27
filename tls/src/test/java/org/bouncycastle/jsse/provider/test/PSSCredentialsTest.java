package org.bouncycastle.jsse.provider.test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import junit.framework.TestCase;

public class PSSCredentialsTest
    extends TestCase
{
    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    private static final String HOST = "localhost";

    static class PSSClient
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final String protocol;
        private final KeyStore trustStore;
        private final KeyStore clientStore;
        private final char[] clientKeyPass;
        private final CountDownLatch latch;

        PSSClient(int port, String protocol, KeyStore clientStore, char[] clientKeyPass,
            X509Certificate trustAnchor) throws GeneralSecurityException, IOException
        {
            KeyStore trustStore = createKeyStore();
            trustStore.setCertificateEntry("server", trustAnchor);

            this.port = port;
            this.protocol = protocol;
            this.trustStore = trustStore;
            this.clientStore = clientStore;
            this.clientKeyPass = clientKeyPass;
            this.latch = new CountDownLatch(1);
        }

        public Exception call() throws Exception
        {
            try
            {
                TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX",
                    ProviderUtils.PROVIDER_NAME_BCJSSE);
                trustMgrFact.init(trustStore);

                KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX",
                    ProviderUtils.PROVIDER_NAME_BCJSSE);
                keyMgrFact.init(clientStore, clientKeyPass);

                SSLContext clientContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
                clientContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(),
                    SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

                SSLSocketFactory fact = clientContext.getSocketFactory();
                SSLSocket cSock = (SSLSocket)fact.createSocket(HOST, port);
                cSock.setEnabledProtocols(new String[]{ protocol });

                SSLSession session = cSock.getSession();
                assertNotNull(session);
                assertFalse("SSL_NULL_WITH_NULL_NULL".equals(session.getCipherSuite()));
                assertEquals("CN=Test CA Certificate", session.getLocalPrincipal().getName());
                assertEquals("CN=Test CA Certificate", session.getPeerPrincipal().getName());

                TestProtocolUtil.doClientProtocol(cSock, "Hello");
            }
            finally
            {
                latch.countDown();
            }

            return null;
        }

        public void await()
            throws InterruptedException
        {
            latch.await();
        }
    }

    static class PSSServer
        implements TestProtocolUtil.BlockingCallable
    {
        private final String protocol;
        private final SSLServerSocket sSock;
        private final CountDownLatch latch;

        PSSServer(int port, String protocol, KeyStore serverStore, char[] keyPass, X509Certificate trustAnchor)
            throws GeneralSecurityException, IOException
        {
            KeyStore trustStore = createKeyStore();
            trustStore.setCertificateEntry("client", trustAnchor);

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX",
                ProviderUtils.PROVIDER_NAME_BCJSSE);
            keyMgrFact.init(serverStore, keyPass);

            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX",
                ProviderUtils.PROVIDER_NAME_BCJSSE);
            trustMgrFact.init(trustStore);

            SSLContext serverContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
            serverContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(),
                SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

            SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
            this.sSock = (SSLServerSocket)fact.createServerSocket(port);

            SSLUtils.enableAll(sSock);
            sSock.setNeedClientAuth(true);

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
                assertEquals("CN=Test CA Certificate", session.getLocalPrincipal().getName());
                assertEquals("CN=Test CA Certificate", session.getPeerPrincipal().getName());

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
        implTestPSSCredentials("TLSv1.2");
    }

    public void test13() throws Exception
    {
        implTestPSSCredentials("TLSv1.3");
    }

    private void implTestPSSCredentials(String protocol) throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        KeyPair caKeyPair = TestUtils.generatePSSKeyPair();
        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore serverKs = createKeyStore();
        serverKs.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        KeyStore clientKs = createKeyStore();
        clientKs.setKeyEntry("client", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        PSSServer server = new PSSServer(0, protocol, serverKs, keyPass, caCert);
        TestProtocolUtil.runClientAndServer(server,
            new PSSClient(server.getPort(), protocol, clientKs, keyPass, caCert));
    }

    private static KeyStore createKeyStore() throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        return keyStore;
    }
}
