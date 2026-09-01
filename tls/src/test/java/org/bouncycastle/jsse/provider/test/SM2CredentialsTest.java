package org.bouncycastle.jsse.provider.test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jsse.BCX509ExtendedKeyManager;

import junit.framework.TestCase;

/**
 * Tests for TLS 1.3 with SM2 credentials and the RFC 8998 ShangMi cipher suites (github #2416).
 * The RFC 8998 profile requires explicit configuration in BCJSSE: the curveSM2 named group and
 * the sm2sig_sm3 signature scheme are not enabled by default.
 */
public class SM2CredentialsTest
    extends TestCase
{
    private static final String HOST = "localhost";

    private static final String PROPERTY_NAMED_GROUPS = "jdk.tls.namedGroups";
    private static final String PROPERTY_CLIENT_SIGSCHEMES = "jdk.tls.client.SignatureSchemes";
    private static final String PROPERTY_SERVER_SIGSCHEMES = "jdk.tls.server.SignatureSchemes";

    protected void setUp()
    {
        ProviderUtils.setupHighPriority(false);

        System.setProperty(PROPERTY_NAMED_GROUPS, "curveSM2");
        System.setProperty(PROPERTY_CLIENT_SIGSCHEMES, "sm2sig_sm3");
        System.setProperty(PROPERTY_SERVER_SIGSCHEMES, "sm2sig_sm3");
    }

    protected void tearDown()
    {
        System.clearProperty(PROPERTY_NAMED_GROUPS);
        System.clearProperty(PROPERTY_CLIENT_SIGSCHEMES);
        System.clearProperty(PROPERTY_SERVER_SIGSCHEMES);
    }

    public void testKeyManagerSelectsSM2ForTls13KeyType() throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        KeyPair keyPair = TestUtils.generateECKeyPair("sm2p256v1");
        X509Certificate cert = TestUtils.createSelfSignedCert("CN=Test CA Certificate", "SM3withSM2", keyPair);

        KeyStore ks = createKeyStore();
        ks.setKeyEntry("sm2", keyPair.getPrivate(), keyPass, new X509Certificate[]{ cert });

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);
        kmf.init(ks, keyPass);

        KeyManager[] keyManagers = kmf.getKeyManagers();
        BCX509ExtendedKeyManager keyManager = (BCX509ExtendedKeyManager)keyManagers[0];

        // NOTE: This depends on the value of JsseUtils.getKeyType13("EC", NamedGroup.curveSM2)
        String keyType = "EC/sm2p256v1";

        assertNotNull(keyManager.chooseServerAlias(keyType, null, null));
        assertNotNull(keyManager.chooseClientAlias(new String[]{ keyType }, null, null));
    }

    public void test13_SM4_CCM_SM3() throws Exception
    {
        implTestSM2Credentials("TLS_SM4_CCM_SM3");
    }

    public void test13_SM4_GCM_SM3() throws Exception
    {
        implTestSM2Credentials("TLS_SM4_GCM_SM3");
    }

    private void implTestSM2Credentials(String cipherSuite) throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        KeyPair caKeyPair = TestUtils.generateECKeyPair("sm2p256v1");
        X509Certificate caCert = TestUtils.createSelfSignedCert("CN=Test CA Certificate", "SM3withSM2", caKeyPair);

        KeyStore serverKs = createKeyStore();
        serverKs.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        KeyStore clientKs = createKeyStore();
        clientKs.setKeyEntry("client", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        SM2Server server = new SM2Server(0, cipherSuite, serverKs, keyPass, caCert);
        TestProtocolUtil.runClientAndServer(server,
            new SM2Client(server.getPort(), cipherSuite, clientKs, keyPass, caCert));
    }

    private static KeyStore createKeyStore() throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        return keyStore;
    }

    static class SM2Client
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final String cipherSuite;
        private final KeyStore trustStore;
        private final KeyStore clientStore;
        private final char[] clientKeyPass;
        private final CountDownLatch latch;

        SM2Client(int port, String cipherSuite, KeyStore clientStore, char[] clientKeyPass,
            X509Certificate trustAnchor) throws GeneralSecurityException, IOException
        {
            KeyStore trustStore = createKeyStore();
            trustStore.setCertificateEntry("server", trustAnchor);

            this.port = port;
            this.cipherSuite = cipherSuite;
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
                cSock.setEnabledProtocols(new String[]{ "TLSv1.3" });
                cSock.setEnabledCipherSuites(new String[]{ cipherSuite });

                SSLSession session = cSock.getSession();
                assertNotNull(session);
                assertEquals(cipherSuite, session.getCipherSuite());
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

    static class SM2Server
        implements TestProtocolUtil.BlockingCallable
    {
        private final String cipherSuite;
        private final SSLServerSocket sSock;
        private final CountDownLatch latch;

        SM2Server(int port, String cipherSuite, KeyStore serverStore, char[] keyPass, X509Certificate trustAnchor)
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

            this.cipherSuite = cipherSuite;
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
                sslSock.setEnabledProtocols(new String[]{ "TLSv1.3" });

                SSLSession session = sslSock.getSession();
                assertNotNull(session);
                assertEquals(cipherSuite, session.getCipherSuite());
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
}
