package org.bouncycastle.jsse.provider.test;

import java.security.SecureRandom;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

public class CipherSuitesTestCase extends TestCase
{
    private static String getName(CipherSuitesTestConfig config)
    {
        String category = config.category;
        String prefix = (null == category || category.length() < 1)
            ?   ""
            :   (category + " ");

        return prefix + config.protocol + " : " + config.cipherSuite;
    }

    protected final CipherSuitesTestConfig config;

    public CipherSuitesTestCase(String name)
    {
        super(name);

        this.config = null;
    }

    public CipherSuitesTestCase(CipherSuitesTestConfig config)
    {
        super(getName(config));

        this.config = config;
    }

    protected void setUp()
    {
        if (config != null)
        {
            ProviderUtils.setupHighPriority(config.fips);
        }
    }

    public void testDummy()
    {
        // Avoid "No tests found" warning from junit
    }

    protected void runTest() throws Throwable
    {
        // Disable the test if it is not being run via CipherSuitesTestSuite
        if (config == null)
        {
            return;
        }

        int port = PORT_NO.incrementAndGet();

        SSLContext clientContext = createClientContext();
        SSLContext serverContext = createServerContext();

        runTestConnection(port, clientContext, serverContext);
        runTestConnection(port, clientContext, serverContext);
    }

    private void runTestConnection(int port, SSLContext clientContext, SSLContext serverContext) throws Throwable
    {
        SimpleServer server = new SimpleServer(serverContext, port, config);
        SimpleClient client = new SimpleClient(clientContext, port, config);

        TestProtocolUtil.runClientAndServer(server, client);

        if (!"TLSv1.3".equals(config.protocol))
        {
            TestCase.assertNotNull(server.tlsUnique);
            TestCase.assertNotNull(client.tlsUnique);
        }
        TestCase.assertTrue(Arrays.areEqual(server.tlsUnique, client.tlsUnique));
    }

    private SSLContext createClientContext() throws Exception
    {
        TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX",
            ProviderUtils.PROVIDER_NAME_BCJSSE);

        trustMgrFact.init(config.clientTrustStore);

        SSLContext clientContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);

        clientContext.init(null, trustMgrFact.getTrustManagers(),
            SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

        return clientContext;
    }

    private SSLContext createServerContext() throws Exception
    {
        KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);

        keyMgrFact.init(config.serverKeyStore, config.serverPassword);

        SSLContext serverContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);

        serverContext.init(keyMgrFact.getKeyManagers(), null,
            SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

        return serverContext;
    }

    private static final String HOST = "localhost";
    private static final AtomicInteger PORT_NO = new AtomicInteger(9100);

    static class SimpleClient
        implements TestProtocolUtil.BlockingCallable
    {
        private final SSLContext clientContext;
        private final int port;
        private final CipherSuitesTestConfig config;
        private final CountDownLatch latch;
        private byte[] tlsUnique = null;

        SimpleClient(SSLContext clientContext, int port, CipherSuitesTestConfig config)
        {
            this.clientContext = clientContext;
            this.port = port;
            this.config = config;
            this.latch = new CountDownLatch(1);
        }

        public Exception call() throws Exception
        {
            try
            {
                SSLSocketFactory fact = clientContext.getSocketFactory();
                SSLSocket cSock = (SSLSocket)fact.createSocket(HOST, port);

                cSock.setEnabledCipherSuites(new String[]{ config.cipherSuite });
                cSock.setEnabledProtocols(new String[]{ config.protocol });

                if (cSock instanceof BCSSLSocket)
                {
                    BCSSLSocket bcSock = (BCSSLSocket)cSock;

                    BCSSLParameters bcParams = new BCSSLParameters();
                    bcParams.setApplicationProtocols(new String[]{ "http/1.1", "h2" });

                    bcSock.setParameters(bcParams);
                    BCSSLConnection bcConn = bcSock.getConnection();
                    if (bcConn != null)
                    {
                        String alpn = bcConn.getApplicationProtocol();
                        System.out.println("Client ALPN: '" + alpn + "'");
                    }
                }

                this.tlsUnique = TestUtils.getChannelBinding(cSock, "tls-unique");

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

    static class SimpleServer
        implements TestProtocolUtil.BlockingCallable
    {
        private final SSLContext serverContext;
        private final int port;
        private final CipherSuitesTestConfig config;
        private final CountDownLatch latch;
        private byte[] tlsUnique = null;

        SimpleServer(SSLContext serverContext, int port, CipherSuitesTestConfig config)
        {
            this.serverContext = serverContext;
            this.port = port;
            this.config = config;
            this.latch = new CountDownLatch(1);
        }

        public Exception call() throws Exception
        {
            try
            {
                SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
                SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(port);

                sSock.setEnabledCipherSuites(new String[]{ config.cipherSuite });
                sSock.setEnabledProtocols(new String[]{ config.protocol });

                latch.countDown();

                SSLSocket sslSock = (SSLSocket)sSock.accept();
                sslSock.setUseClientMode(false);

//                sslSock.setHandshakeApplicationProtocolSelector((socket, protocols) ->
//                {
//                    if (protocols.contains("h2"))
//                    {
//                        return "h2";
//                    }
//                    if (protocols.contains("http/1.1"))
//                    {
//                        return "http/1.1";
//                    }
//                    return null;
//                });

                if (sslSock instanceof BCSSLSocket)
                {
                    BCSSLSocket bcSock = (BCSSLSocket)sslSock;

                    BCSSLParameters bcParams = new BCSSLParameters();
                    bcParams.setApplicationProtocols(new String[]{ "h2", "http/1.1" });

                    bcSock.setParameters(bcParams);

//                    bcSock.setBCHandshakeApplicationProtocolSelector(new BCApplicationProtocolSelector<SSLSocket>()
//                    {
//                        public String select(SSLSocket transport, List<String> protocols)
//                        {
//                            if (protocols.contains("h2"))
//                            {
//                                return "h2";
//                            }
//                            if (protocols.contains("http/1.1"))
//                            {
//                                return "http/1.1";
//                            }
//                            return null;
//                        }
//                    });

                    BCSSLConnection bcConn = bcSock.getConnection();
                    if (bcConn != null)
                    {
                        String alpn = bcConn.getApplicationProtocol();
                        System.out.println("Server ALPN: '" + alpn + "'");
                    }
                }

                this.tlsUnique = TestUtils.getChannelBinding(sslSock, "tls-unique");

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
