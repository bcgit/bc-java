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

import org.bouncycastle.tls.NamedGroup;

import junit.framework.TestCase;

public class ECDSACredentialsTest
    extends TestCase
{
    private static final String HOST = "localhost";
    private static final int PORT_NO_12_brainpoolP256r1 = 9030;
    private static final int PORT_NO_12_brainpoolP384r1 = 9031;
    private static final int PORT_NO_12_brainpoolP512r1 = 9032;
    private static final int PORT_NO_12_secp256r1 = 9033;
    private static final int PORT_NO_12_secp384r1 = 9034;
    private static final int PORT_NO_12_secp521r1 = 9035;
    private static final int PORT_NO_13_brainpoolP256r1 = 9036;
    private static final int PORT_NO_13_brainpoolP384r1 = 9037;
    private static final int PORT_NO_13_brainpoolP512r1 = 9038;
    private static final int PORT_NO_13_secp256r1 = 9039;
    private static final int PORT_NO_13_secp384r1 = 9040;
    private static final int PORT_NO_13_secp521r1 = 9041;

    private static final String PROPERTY_NAMED_GROUPS = "jdk.tls.namedGroups";

    protected void setUp()
    {
        // NOTE: SunEC doesn't support brainpool curves until JDK 11
        ProviderUtils.setupHighPriority(false);
//        ProviderUtils.setupLowPriority(false);

        System.setProperty(PROPERTY_NAMED_GROUPS,
            "secp256r1,secp384r1,secp521r1," +
            "brainpoolP256r1tls13,brainpoolP384r1tls13,brainpoolP512r1tls13," +
            "brainpoolP256r1,brainpoolP384r1,brainpoolP512r1");
    }

    protected void tearDown()
    {
        System.clearProperty(PROPERTY_NAMED_GROUPS);
    }

    public void test12_brainpoolP256r1() throws Exception
    {
        implTestECDSACredentials(PORT_NO_12_brainpoolP256r1, "TLSv1.2", NamedGroup.brainpoolP256r1);
    }

    public void test12_brainpoolP384r1() throws Exception
    {
        implTestECDSACredentials(PORT_NO_12_brainpoolP384r1, "TLSv1.2", NamedGroup.brainpoolP384r1);
    }

    public void test12_brainpoolP512r1() throws Exception
    {
        implTestECDSACredentials(PORT_NO_12_brainpoolP512r1, "TLSv1.2", NamedGroup.brainpoolP512r1);
    }

    public void test12_secp256r1() throws Exception
    {
        implTestECDSACredentials(PORT_NO_12_secp256r1, "TLSv1.2", NamedGroup.secp256r1);
    }

    public void test12_secp384r1() throws Exception
    {
        implTestECDSACredentials(PORT_NO_12_secp384r1, "TLSv1.2", NamedGroup.secp384r1);
    }

    public void test12_secp521r1() throws Exception
    {
        implTestECDSACredentials(PORT_NO_12_secp521r1, "TLSv1.2", NamedGroup.secp521r1);
    }

    public void test13_brainpoolP256r1tls13() throws Exception
    {
        implTestECDSACredentials(PORT_NO_13_brainpoolP256r1, "TLSv1.3", NamedGroup.brainpoolP256r1tls13);
    }

    public void test13_brainpoolP384r1tls13() throws Exception
    {
        implTestECDSACredentials(PORT_NO_13_brainpoolP384r1, "TLSv1.3", NamedGroup.brainpoolP384r1tls13);
    }

    public void test13_brainpoolP512r1tls13() throws Exception
    {
        implTestECDSACredentials(PORT_NO_13_brainpoolP512r1, "TLSv1.3", NamedGroup.brainpoolP512r1tls13);
    }

    public void test13_secp256r1() throws Exception
    {
        implTestECDSACredentials(PORT_NO_13_secp256r1, "TLSv1.3", NamedGroup.secp256r1);
    }

    public void test13_secp384r1() throws Exception
    {
        implTestECDSACredentials(PORT_NO_13_secp384r1, "TLSv1.3", NamedGroup.secp384r1);
    }

    public void test13_secp521r1() throws Exception
    {
        implTestECDSACredentials(PORT_NO_13_secp521r1, "TLSv1.3", NamedGroup.secp521r1);
    }

    private void implTestECDSACredentials(int port, String protocol, int namedGroup) throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        String curveName = NamedGroup.getCurveName(namedGroup);
        KeyPair caKeyPair = TestUtils.generateECKeyPair(curveName);
        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore serverKs = createKeyStore();
        serverKs.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[] { caCert });

        KeyStore clientKs = createKeyStore();
        clientKs.setKeyEntry("client", caKeyPair.getPrivate(), keyPass, new X509Certificate[] { caCert });

        TestProtocolUtil.runClientAndServer(new ECDSAServer(port, protocol, serverKs, keyPass, caCert),
            new ECDSAClient(port, protocol, clientKs, keyPass, caCert));
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

    static class ECDSAClient
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final String protocol;
        private final KeyStore trustStore;
        private final KeyStore clientStore;
        private final char[] clientKeyPass;
        private final CountDownLatch latch;

        ECDSAClient(int port, String protocol, KeyStore clientStore, char[] clientKeyPass,
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

    static class ECDSAServer
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final String protocol;
        private final KeyStore serverStore;
        private final char[] keyPass;
        private final KeyStore trustStore;
        private final CountDownLatch latch;

        ECDSAServer(int port, String protocol, KeyStore serverStore, char[] keyPass, X509Certificate trustAnchor)
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
}
