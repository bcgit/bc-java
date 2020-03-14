package org.bouncycastle.jsse.provider.test;

import static org.junit.Assert.assertNotEquals;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import junit.framework.TestCase;

public class EdDSACredentialsTest
    extends TestCase
{
    protected void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleJsseProvider());
        }
    }

    private static final String HOST = "localhost";
    private static final int PORT_NO_ED25519 = 9017;
    private static final int PORT_NO_ED448 = 9018;

    public static class EdDSAClient
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final KeyStore trustStore;
        private final KeyStore clientStore;
        private final char[] clientKeyPass;
        private final CountDownLatch latch;

        public EdDSAClient(int port, KeyStore clientStore, char[] clientKeyPass, X509Certificate trustAnchor)
            throws GeneralSecurityException, IOException
        {
            this.port = port;
            this.trustStore = KeyStore.getInstance("JKS");
            trustStore.load(null, null);
            trustStore.setCertificateEntry("server", trustAnchor);

            this.clientStore = clientStore;
            this.clientKeyPass = clientKeyPass;
            this.latch = new CountDownLatch(1);
        }

        public Exception call() throws Exception
        {
            try
            {
                TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX",
                    BouncyCastleJsseProvider.PROVIDER_NAME);

                trustMgrFact.init(trustStore);

                KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX",
                    BouncyCastleJsseProvider.PROVIDER_NAME);

                keyMgrFact.init(clientStore, clientKeyPass);

                SSLContext clientContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);

                clientContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(),
                    SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));

                SSLSocketFactory fact = clientContext.getSocketFactory();
                SSLSocket cSock = (SSLSocket)fact.createSocket(HOST, port);

                SSLSession session = cSock.getSession();
                assertNotNull(session);
                assertNotEquals("SSL_NULL_WITH_NULL_NULL", session.getCipherSuite());
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

    public static class EdDSAServer
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final KeyStore serverStore;
        private final char[] keyPass;
        private final KeyStore trustStore;
        private final CountDownLatch latch;

        EdDSAServer(int port, KeyStore serverStore, char[] keyPass, X509Certificate trustAnchor)
            throws GeneralSecurityException, IOException
        {
            this.port = port;
            this.serverStore = serverStore;
            this.keyPass = keyPass;
            this.trustStore = KeyStore.getInstance("JKS");
            trustStore.load(null, null);
            trustStore.setCertificateEntry("client", trustAnchor);

            this.latch = new CountDownLatch(1);
        }

        public Exception call() throws Exception
        {
            try
            {
                KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX",
                    BouncyCastleJsseProvider.PROVIDER_NAME);

                keyMgrFact.init(serverStore, keyPass);

                TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX",
                    BouncyCastleJsseProvider.PROVIDER_NAME);

                trustMgrFact.init(trustStore);

                SSLContext serverContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);

                serverContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(),
                    SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));

                SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
                SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(port);

                SSLUtils.enableAll(sSock);
                sSock.setNeedClientAuth(true);

                latch.countDown();

                SSLSocket sslSock = (SSLSocket)sSock.accept();

                SSLSession session = sslSock.getSession();
                assertNotNull(session);
                assertNotEquals("SSL_NULL_WITH_NULL_NULL", session.getCipherSuite());
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

    public void testEd25519Credentials() throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        KeyPair caKeyPair = TestUtils.generateEd25519KeyPair();
        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore serverKs = createKeyStore();
        serverKs.load(null, null);
        serverKs.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        KeyStore clientKs = createKeyStore();
        clientKs.load(null, null);
        clientKs.setKeyEntry("client", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        TestProtocolUtil.runClientAndServer(new EdDSAServer(PORT_NO_ED25519, serverKs, keyPass, caCert),
            new EdDSAClient(PORT_NO_ED25519, clientKs, keyPass, caCert));
    }

    public void testEd448Credentials() throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        KeyPair caKeyPair = TestUtils.generateEd448KeyPair();
        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore serverKs = createKeyStore();
        serverKs.load(null, null);
        serverKs.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        KeyStore clientKs = createKeyStore();
        clientKs.load(null, null);
        clientKs.setKeyEntry("client", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        TestProtocolUtil.runClientAndServer(new EdDSAServer(PORT_NO_ED448, serverKs, keyPass, caCert),
            new EdDSAClient(PORT_NO_ED448, clientKs, keyPass, caCert));
    }

    private static KeyStore createKeyStore() throws GeneralSecurityException
    {
        /*
         * NOTE: At the time of writing, default JKS implementation can't recover PKCS8 private keys
         * with version != 0, which e.g. is the case when a public key is included, which the BC
         * provider currently does for EdDSA.
         */
//        return KeyStore.getInstance("JKS");
        return KeyStore.getInstance("PKCS12");
    }
}
