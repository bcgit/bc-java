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

public class EdDSACredentialsTest
    extends TestCase
{
    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    private static final String HOST = "localhost";
    private static final int PORT_NO_12_ED25519 = 9020;
    private static final int PORT_NO_12_ED448 = 9021;
    private static final int PORT_NO_13_ED25519 = 9022;
    private static final int PORT_NO_13_ED448 = 9023;

    static class EdDSAClient
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final String protocol;
        private final KeyStore trustStore;
        private final KeyStore clientStore;
        private final char[] clientKeyPass;
        private final CountDownLatch latch;

        EdDSAClient(int port, String protocol, KeyStore clientStore, char[] clientKeyPass,
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

    static class EdDSAServer
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final String protocol;
        private final KeyStore serverStore;
        private final char[] keyPass;
        private final KeyStore trustStore;
        private final CountDownLatch latch;

        EdDSAServer(int port, String protocol, KeyStore serverStore, char[] keyPass, X509Certificate trustAnchor)
            throws GeneralSecurityException, IOException
        {
            KeyStore trustStore = createKeyStore();
            trustStore.setCertificateEntry("client", trustAnchor);

            this.port = port;
            this.protocol = protocol;
            this.serverStore = serverStore;
            this.keyPass = keyPass;
            this.trustStore = trustStore;
            this.latch = new CountDownLatch(1);
        }

        public Exception call() throws Exception
        {
            try
            {
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
                SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(port);

                SSLUtils.enableAll(sSock);
                sSock.setNeedClientAuth(true);

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

    public void test12_Ed25519() throws Exception
    {
        implTestEdDSACredentials(PORT_NO_12_ED25519, "TLSv1.2", TestUtils.generateEd25519KeyPair());
    }

    public void test12_Ed448() throws Exception
    {
        implTestEdDSACredentials(PORT_NO_12_ED448, "TLSv1.2", TestUtils.generateEd448KeyPair());
    }

    public void test13_Ed25519() throws Exception
    {
        implTestEdDSACredentials(PORT_NO_13_ED25519, "TLSv1.3", TestUtils.generateEd25519KeyPair());
    }

    public void test13_Ed448() throws Exception
    {
        implTestEdDSACredentials(PORT_NO_13_ED448, "TLSv1.3", TestUtils.generateEd448KeyPair());
    }

    private void implTestEdDSACredentials(int port, String protocol, KeyPair caKeyPair) throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore serverKs = createKeyStore();
        serverKs.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        KeyStore clientKs = createKeyStore();
        clientKs.setKeyEntry("client", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        TestProtocolUtil.runClientAndServer(new EdDSAServer(port, protocol, serverKs, keyPass, caCert),
            new EdDSAClient(port, protocol, clientKs, keyPass, caCert));
    }

    private static KeyStore createKeyStore() throws GeneralSecurityException, IOException
    {
        /*
         * NOTE: At the time of writing, default JKS implementation can't recover PKCS8 private keys
         * with version != 0, which e.g. is the case when a public key is included, which the BC
         * provider currently does for EdDSA.
         */
//        KeyStore keyStore = KeyStore.getInstance("JKS");
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        return keyStore;
    }
}
