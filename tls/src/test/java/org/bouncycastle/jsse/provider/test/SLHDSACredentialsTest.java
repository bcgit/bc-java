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

public class SLHDSACredentialsTest
    extends TestCase
{
    private static final String PROPERTY_CLIENT_SIGNATURE_SCHEMES = "jdk.tls.client.SignatureSchemes";
    private static final String PROPERTY_SERVER_SIGNATURE_SCHEMES = "jdk.tls.server.SignatureSchemes";
    
    private static final String PROPERTY_MAX_HANDSHAKE_MESSAGE_SIZE = "jdk.tls.maxHandshakeMessageSize";

    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);

        String signatureSchemes =
            "slhdsa_sha2_128s, slhdsa_sha2_128f, " +
            "slhdsa_sha2_192s, slhdsa_sha2_192f, " +
            "slhdsa_sha2_256s, slhdsa_sha2_256f, " +
            "slhdsa_shake_128s, slhdsa_shake_128f, " +
            "slhdsa_shake_192s, slhdsa_shake_192f, " +
            "slhdsa_shake_256s, slhdsa_shake_256f";

        System.setProperty(PROPERTY_CLIENT_SIGNATURE_SCHEMES, signatureSchemes);
        System.setProperty(PROPERTY_SERVER_SIGNATURE_SCHEMES, signatureSchemes);

        System.setProperty(PROPERTY_MAX_HANDSHAKE_MESSAGE_SIZE, "65536");
    }

    protected void tearDown()
    {
        System.clearProperty(PROPERTY_CLIENT_SIGNATURE_SCHEMES);
        System.clearProperty(PROPERTY_SERVER_SIGNATURE_SCHEMES);

        System.clearProperty(PROPERTY_MAX_HANDSHAKE_MESSAGE_SIZE);
    }

    private static final String HOST = "localhost";
    private static final int PORT_NO_13_SLHDSA_SHA2_128F = 9070;
    private static final int PORT_NO_13_SLHDSA_SHA2_192F = 9071;
    private static final int PORT_NO_13_SLHDSA_SHA2_256F = 9072;
    private static final int PORT_NO_13_SLHDSA_SHAKE_128F = 9073;
    private static final int PORT_NO_13_SLHDSA_SHAKE_192F = 9074;
    private static final int PORT_NO_13_SLHDSA_SHAKE_256F = 9075;
//    private static final int PORT_NO_13_SLHDSA_SHA2_128S = 9080;
//    private static final int PORT_NO_13_SLHDSA_SHA2_192S = 9081;
//    private static final int PORT_NO_13_SLHDSA_SHA2_256S = 9082;
//    private static final int PORT_NO_13_SLHDSA_SHAKE_128S = 9083;
//    private static final int PORT_NO_13_SLHDSA_SHAKE_192S = 9084;
//    private static final int PORT_NO_13_SLHDSA_SHAKE_256S = 9085;

    static class SLHDSAClient
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final String protocol;
        private final KeyStore trustStore;
        private final KeyStore clientStore;
        private final char[] clientKeyPass;
        private final CountDownLatch latch;

        SLHDSAClient(int port, String protocol, KeyStore clientStore, char[] clientKeyPass,
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

    static class SLHDSAServer
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final String protocol;
        private final KeyStore serverStore;
        private final char[] keyPass;
        private final KeyStore trustStore;
        private final CountDownLatch latch;

        SLHDSAServer(int port, String protocol, KeyStore serverStore, char[] keyPass, X509Certificate trustAnchor)
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

    public void test13_SLHDSA_SHA2_128F() throws Exception
    {
        implTestSLHDSACredentials(PORT_NO_13_SLHDSA_SHA2_128F, "TLSv1.3",
            TestUtils.generateSLHDSAKeyPair("SLH-DSA-SHA2-128F"));
    }

    public void test13_SLHDSA_SHA2_192F() throws Exception
    {
        implTestSLHDSACredentials(PORT_NO_13_SLHDSA_SHA2_192F, "TLSv1.3",
            TestUtils.generateSLHDSAKeyPair("SLH-DSA-SHA2-192F"));
    }

    public void test13_SLHDSA_SHA2_256F() throws Exception
    {
        implTestSLHDSACredentials(PORT_NO_13_SLHDSA_SHA2_256F, "TLSv1.3",
            TestUtils.generateSLHDSAKeyPair("SLH-DSA-SHA2-256F"));
    }

    public void test13_SLHDSA_SHAKE_128F() throws Exception
    {
        implTestSLHDSACredentials(PORT_NO_13_SLHDSA_SHAKE_128F, "TLSv1.3",
            TestUtils.generateSLHDSAKeyPair("SLH-DSA-SHAKE-128F"));
    }

    public void test13_SLHDSA_SHAKE_192F() throws Exception
    {
        implTestSLHDSACredentials(PORT_NO_13_SLHDSA_SHAKE_192F, "TLSv1.3",
            TestUtils.generateSLHDSAKeyPair("SLH-DSA-SHAKE-192F"));
    }

    public void test13_SLHDSA_SHAKE_256F() throws Exception
    {
        implTestSLHDSACredentials(PORT_NO_13_SLHDSA_SHAKE_256F, "TLSv1.3",
            TestUtils.generateSLHDSAKeyPair("SLH-DSA-SHAKE-256F"));
    }

    // TODO[tls-slhdsa] Too slow to run routinely
/*
    public void test13_SLHDSA_SHA2_128S() throws Exception
    {
        implTestSLHDSACredentials(PORT_NO_13_SLHDSA_SHA2_128S, "TLSv1.3",
            TestUtils.generateSLHDSAKeyPair("SLH-DSA-SHA2-128S"));
    }

    public void test13_SLHDSA_SHA2_192S() throws Exception
    {
        implTestSLHDSACredentials(PORT_NO_13_SLHDSA_SHA2_192S, "TLSv1.3",
            TestUtils.generateSLHDSAKeyPair("SLH-DSA-SHA2-192S"));
    }

    public void test13_SLHDSA_SHA2_256S() throws Exception
    {
        implTestSLHDSACredentials(PORT_NO_13_SLHDSA_SHA2_256S, "TLSv1.3",
            TestUtils.generateSLHDSAKeyPair("SLH-DSA-SHA2-256S"));
    }

    public void test13_SLHDSA_SHAKE_128S() throws Exception
    {
        implTestSLHDSACredentials(PORT_NO_13_SLHDSA_SHAKE_128S, "TLSv1.3",
            TestUtils.generateSLHDSAKeyPair("SLH-DSA-SHAKE-128S"));
    }

    public void test13_SLHDSA_SHAKE_192S() throws Exception
    {
        implTestSLHDSACredentials(PORT_NO_13_SLHDSA_SHAKE_192S, "TLSv1.3",
            TestUtils.generateSLHDSAKeyPair("SLH-DSA-SHAKE-192S"));
    }

    public void test13_SLHDSA_SHAKE_256S() throws Exception
    {
        implTestSLHDSACredentials(PORT_NO_13_SLHDSA_SHAKE_256S, "TLSv1.3",
            TestUtils.generateSLHDSAKeyPair("SLH-DSA-SHAKE-256S"));
    }
*/

    private void implTestSLHDSACredentials(int port, String protocol, KeyPair caKeyPair) throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore serverKs = createKeyStore();
        serverKs.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        KeyStore clientKs = createKeyStore();
        clientKs.setKeyEntry("client", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        TestProtocolUtil.runClientAndServer(new SLHDSAServer(port, protocol, serverKs, keyPass, caCert),
            new SLHDSAClient(port, protocol, clientKs, keyPass, caCert));
    }

    private static KeyStore createKeyStore() throws GeneralSecurityException, IOException
    {
        /*
         * NOTE: At the time of writing, default JKS implementation can't recover PKCS8 private keys
         * with version != 0, which e.g. is the case when a public key is included, which the BC
         * provider currently does for MLDSA.
         */
//        KeyStore keyStore = KeyStore.getInstance("JKS");
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        return keyStore;
    }
}
