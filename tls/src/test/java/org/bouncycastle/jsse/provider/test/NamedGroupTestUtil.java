package org.bouncycastle.jsse.provider.test;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/**
 * Machinery for driving a TLS 1.3 handshake over a single named group, shared by the tests that
 * ask which groups are usable and which are offered by default.
 */
class NamedGroupTestUtil
{
    private static final String HOST = "localhost";
    private static final AtomicInteger PORT_NO = new AtomicInteger(19700);

    static final char[] KEY_PASSWORD = "keyPassword".toCharArray();

    /**
     * A key store holding an RSA credential and the trust store for it. RSA rather than EC because
     * a peer restricted to a single ML-KEM group offers no EC curve, which would leave the
     * ecdsa_*-family signature schemes unusable and mask what is under test behind an unrelated
     * "no credentials" failure.
     */
    static KeyStore[] createRSACredential()
        throws Exception
    {
        KeyPair caKeyPair = TestUtils.generateRSAKeyPair();
        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("server", caKeyPair.getPrivate(), KEY_PASSWORD, new X509Certificate[]{ caCert });

        KeyStore ts = KeyStore.getInstance("JKS");
        ts.load(null, null);
        ts.setCertificateEntry("ca", caCert);

        return new KeyStore[]{ ks, ts };
    }

    static SSLContext createServerContext(Provider tlsProv, KeyStore ks)
        throws Exception
    {
        KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", tlsProv);
        keyMgrFact.init(ks, KEY_PASSWORD);

        SSLContext serverContext = SSLContext.getInstance("TLS", tlsProv);
        serverContext.init(keyMgrFact.getKeyManagers(), null,
            SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

        return serverContext;
    }

    static SSLContext createClientContext(Provider tlsProv, KeyStore ts)
        throws Exception
    {
        TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX", tlsProv);
        trustMgrFact.init(ts);

        SSLContext clientContext = SSLContext.getInstance("TLS", tlsProv);
        clientContext.init(null, trustMgrFact.getTrustManagers(),
            SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

        return clientContext;
    }

    /**
     * Both ends restricted to namedGroup, so the handshake can only succeed on that group. Fails
     * the calling test if it does not complete.
     */
    static void runNamedGroupTest(String namedGroup, SSLContext clientContext, SSLContext serverContext)
        throws Exception
    {
        int port = PORT_NO.incrementAndGet();

        TestProtocolUtil.runClientAndServer(new NamedGroupServer(serverContext, port, namedGroup),
            new NamedGroupClient(clientContext, port, namedGroup));
    }

    /**
     * Client restricted to namedGroup against a server left at its defaults, reporting whether the
     * exchange completed rather than asserting that it did - so a caller can ask whether a group
     * is one the server offers without configuration.
     */
    static boolean defaultServerAccepts(String namedGroup, SSLContext clientContext, SSLContext serverContext)
        throws Exception
    {
        int port = PORT_NO.incrementAndGet();

        NamedGroupClient client = new NamedGroupClient(clientContext, port, namedGroup);
        NamedGroupServer server = new NamedGroupServer(serverContext, port, null);

        TestProtocolUtil.Task serverTask = new TestProtocolUtil.Task(server);
        Thread serverThread = new Thread(serverTask);
        serverThread.setDaemon(true);
        serverThread.start();
        server.await();

        TestProtocolUtil.Task clientTask = new TestProtocolUtil.Task(client);
        Thread clientThread = new Thread(clientTask);
        clientThread.setDaemon(true);
        clientThread.start();
        client.await();

        serverThread.join();
        clientThread.join();

        return serverTask.getResult() == null && clientTask.getResult() == null;
    }

    private static void restrictToNamedGroup(SSLSocket sock, String namedGroup)
    {
        sock.setEnabledProtocols(new String[]{ "TLSv1.3" });

        if (namedGroup != null && sock instanceof BCSSLSocket)
        {
            BCSSLSocket bcSock = (BCSSLSocket)sock;
            BCSSLParameters bcParams = bcSock.getParameters();
            bcParams.setNamedGroups(new String[]{ namedGroup });
            bcSock.setParameters(bcParams);
        }
    }

    private static class NamedGroupClient
        implements TestProtocolUtil.BlockingCallable
    {
        private final SSLContext clientContext;
        private final int port;
        private final String namedGroup;
        private final CountDownLatch latch = new CountDownLatch(1);

        NamedGroupClient(SSLContext clientContext, int port, String namedGroup)
        {
            this.clientContext = clientContext;
            this.port = port;
            this.namedGroup = namedGroup;
        }

        public Exception call() throws Exception
        {
            try
            {
                SSLSocketFactory fact = clientContext.getSocketFactory();
                SSLSocket cSock = (SSLSocket)fact.createSocket(HOST, port);

                restrictToNamedGroup(cSock, namedGroup);

                TestProtocolUtil.doClientProtocol(cSock, "Hello");

                cSock.close();
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

    /**
     * A null namedGroup leaves the server's own groups at their defaults.
     */
    private static class NamedGroupServer
        implements TestProtocolUtil.BlockingCallable
    {
        private final SSLContext serverContext;
        private final int port;
        private final String namedGroup;
        private final CountDownLatch latch = new CountDownLatch(1);

        NamedGroupServer(SSLContext serverContext, int port, String namedGroup)
        {
            this.serverContext = serverContext;
            this.port = port;
            this.namedGroup = namedGroup;
        }

        public Exception call() throws Exception
        {
            try
            {
                SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
                SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(port);

                sSock.setEnabledProtocols(new String[]{ "TLSv1.3" });

                latch.countDown();

                SSLSocket sslSock = (SSLSocket)sSock.accept();
                sslSock.setUseClientMode(false);

                restrictToNamedGroup(sslSock, namedGroup);

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
