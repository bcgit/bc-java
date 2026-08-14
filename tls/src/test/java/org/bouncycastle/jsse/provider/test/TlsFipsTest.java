package org.bouncycastle.jsse.provider.test;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import junit.framework.TestCase;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/**
 * A test to confirm what the BCJSSE provider actually enables in FIPS mode: the protocol
 * preference, the GCM cipher suites (available when the JcaTlsCrypto supplies a FIPS GCM nonce
 * generator factory), and the ML-KEM based named groups.
 * <p/>
 * Note this is the complement of {@link FipsCipherSuitesTestSuite} /
 * {@link FipsCipherSuitesEngineTestSuite}: those check that nothing <em>outside</em> the FIPS set is
 * exposed, this one checks the FIPS-approved algorithms are in fact there.
 */
public class TlsFipsTest
    extends TestCase
{
    private static final String HOST = "localhost";
    private static final AtomicInteger PORT_NO = new AtomicInteger(19700);

    protected void setUp()
    {
        FipsTestUtils.setupFipsSuite();
    }

    protected void tearDown()
    {
        FipsTestUtils.teardownFipsSuite();
    }

    public void testTLS13()
        throws Exception
    {
        Provider tlsProv = ProviderUtils.getProviderBCJSSE();

        SSLContext clientContext = SSLContext.getInstance("TLS", tlsProv);

        clientContext.init(null, null, null);

        try
        {
            String[] protocols = clientContext.getSupportedSSLParameters().getProtocols();

            assertTrue(protocols[0].equals("TLSv1.3"));
        }
        catch (NoSuchMethodError e)
        {
            // ignore on this jvm, we'll fail elsewhere!
        }
    }

    public void testFipsModeGCM()
        throws Exception
    {
        Set<String> gcm = new HashSet<String>();
        {
            gcm.add("TLS_AES_128_GCM_SHA256");
            gcm.add("TLS_AES_256_GCM_SHA384");

            if (FipsTestUtils.enableGCMCiphersIn12)
            {
                gcm.add("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
                gcm.add("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");
                gcm.add("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
                gcm.add("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
                gcm.add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
                gcm.add("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
                gcm.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
                gcm.add("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");

                if (FipsTestUtils.provAllowRSAKeyExchange)
                {
                    gcm.add("TLS_RSA_WITH_AES_128_GCM_SHA256");
                    gcm.add("TLS_RSA_WITH_AES_256_GCM_SHA384");
                }
            }
        }

        Provider tlsProv = ProviderUtils.getProviderBCJSSE();

        SSLContext sslContext = SSLContext.getInstance("TLS", tlsProv);

        sslContext.init(null, null, SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

        String[] cipherSuites = sslContext.getServerSocketFactory().getSupportedCipherSuites();

        for (int i = 0; i != cipherSuites.length; i++)
        {
            gcm.remove(cipherSuites[i]);
        }

        assertTrue("GCM cipher suites missing in FIPS mode: " + gcm, gcm.isEmpty());
    }

    /**
     * Confirms that the ML-KEM/hybrid named groups classified as FIPS-approved in
     * FipsUtils.isFipsNamedGroup can each complete a TLS 1.3 handshake through the FIPS-mode
     * BCJSSE provider.
     */
    public void testFipsModeMLKEMGroups()
        throws Exception
    {
        String[] namedGroups = new String[]{
            "SecP256r1MLKEM768",
            "SecP384r1MLKEM1024",
            "X25519MLKEM768",
            "MLKEM512",
            "MLKEM768",
            "MLKEM1024",
        };

        Provider tlsProv = ProviderUtils.getProviderBCJSSE();
        char[] keyPass = "keyPassword".toCharArray();

        /*
         * An RSA cert is used rather than EC: the client below is restricted to offering only the
         * single named group under test, so its supported_groups extension omits the plain EC
         * curves entirely. That makes ecdsa_*-family signature schemes unusable (their key type is
         * tied to a specific curve named group), which would otherwise mask what's being tested here
         * behind an unrelated "no credentials" failure. RSA signature schemes carry no such tie.
         */
        KeyPair caKeyPair = TestUtils.generateRSAKeyPair();

        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        KeyStore ts = KeyStore.getInstance("JKS");
        ts.load(null, null);
        ts.setCertificateEntry("ca", caCert);

        for (int i = 0; i != namedGroups.length; i++)
        {
            String namedGroup = namedGroups[i];

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", tlsProv);
            keyMgrFact.init(ks, keyPass);

            SSLContext serverContext = SSLContext.getInstance("TLS", tlsProv);
            serverContext.init(keyMgrFact.getKeyManagers(), null,
                SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX", tlsProv);
            trustMgrFact.init(ts);

            SSLContext clientContext = SSLContext.getInstance("TLS", tlsProv);
            clientContext.init(null, trustMgrFact.getTrustManagers(),
                SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

            runNamedGroupTest(namedGroup, clientContext, serverContext);
        }
    }

    /**
     * The pure ML-KEM groups are FIPS-approved but not offered by default (TLS working group
     * feedback: a key exchange should keep a classical component), so a client asking for one
     * against an otherwise default server has nothing in common with it and the handshake fails.
     * The hybrids are defaults, and still complete against the same server.
     */
    public void testPureMLKEMGroupsNotOfferedByDefault()
        throws Exception
    {
        Provider tlsProv = ProviderUtils.getProviderBCJSSE();
        char[] keyPass = "keyPassword".toCharArray();

        KeyPair caKeyPair = TestUtils.generateRSAKeyPair();
        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        KeyStore ts = KeyStore.getInstance("JKS");
        ts.load(null, null);
        ts.setCertificateEntry("ca", caCert);

        assertFalse("MLKEM768 reached a default-configured server", defaultServerAccepts("MLKEM768", tlsProv, ks, ts, keyPass));
        assertTrue("X25519MLKEM768 refused by a default-configured server",
            defaultServerAccepts("X25519MLKEM768", tlsProv, ks, ts, keyPass));
    }

    /**
     * Run a client restricted to namedGroup against a server left at its defaults, reporting
     * whether the exchange completed rather than asserting it did.
     */
    private static boolean defaultServerAccepts(String namedGroup, Provider tlsProv, KeyStore ks, KeyStore ts,
        char[] keyPass)
        throws Exception
    {
        KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", tlsProv);
        keyMgrFact.init(ks, keyPass);

        SSLContext serverContext = SSLContext.getInstance("TLS", tlsProv);
        serverContext.init(keyMgrFact.getKeyManagers(), null,
            SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

        TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX", tlsProv);
        trustMgrFact.init(ts);

        SSLContext clientContext = SSLContext.getInstance("TLS", tlsProv);
        clientContext.init(null, trustMgrFact.getTrustManagers(),
            SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

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

    private static void runNamedGroupTest(String namedGroup, SSLContext clientContext, SSLContext serverContext)
        throws Exception
    {
        int port = PORT_NO.incrementAndGet();

        NamedGroupClient client = new NamedGroupClient(clientContext, port, namedGroup);
        NamedGroupServer server = new NamedGroupServer(serverContext, port, namedGroup);

        TestProtocolUtil.runClientAndServer(server, client);
    }

    /**
     * Restricts a peer to namedGroup alone, so the handshake can only succeed on that group. Both
     * ends are restricted: the pure ML-KEM groups are not offered by default (see the note in
     * NamedGroupInfo), so a default-configured peer would have nothing in common with a client
     * asking for one. An RSA server credential is used precisely so that narrowing the groups
     * this way does not also strip the curve an ecdsa_* signature scheme would depend on.
     */
    private static void restrictToNamedGroup(SSLSocket sock, String namedGroup)
    {
        sock.setEnabledProtocols(new String[]{ "TLSv1.3" });

        if (sock instanceof BCSSLSocket)
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

                if (namedGroup != null)
                {
                    restrictToNamedGroup(sslSock, namedGroup);
                }
                else
                {
                    sslSock.setEnabledProtocols(new String[]{ "TLSv1.3" });
                }

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
