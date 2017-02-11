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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import junit.framework.TestCase;

public class CipherSuitesTestCase extends TestCase
{
    protected final CipherSuitesTestConfig config;

    public CipherSuitesTestCase(String name)
    {
        super(name);

        this.config = null;
    }

    public CipherSuitesTestCase(CipherSuitesTestConfig config)
    {
        super(config.cipherSuite);

        this.config = config;
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

        TestProtocolUtil.runClientAndServer(new SimpleServer(port, config), new SimpleClient(port, config));
    }

    private static final String HOST = "localhost";
    private static final AtomicInteger PORT_NO = new AtomicInteger(9100);

    static class SimpleClient
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final CipherSuitesTestConfig config;
        private final CountDownLatch latch;

        SimpleClient(int port, CipherSuitesTestConfig config)
        {
            this.port = port;
            this.config = config;
            this.latch = new CountDownLatch(1);
        }

        public Exception call()
            throws Exception
        {
            try
            {
                TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX",
                    BouncyCastleJsseProvider.PROVIDER_NAME);
    
                trustMgrFact.init(config.clientTrustStore);
    
                SSLContext clientContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
    
                clientContext.init(null, trustMgrFact.getTrustManagers(),
                    SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));
    
                SSLSocketFactory fact = clientContext.getSocketFactory();
                SSLSocket cSock = (SSLSocket)fact.createSocket(HOST, port);
    
                cSock.setEnabledCipherSuites(new String[]{ config.cipherSuite });
    
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

    static class SimpleServer
        implements TestProtocolUtil.BlockingCallable
    {
        private final int port;
        private final CipherSuitesTestConfig config;
        private final CountDownLatch latch;

        SimpleServer(int port, CipherSuitesTestConfig config)
        {
            this.port = port;
            this.config = config;
            this.latch = new CountDownLatch(1);
        }

        public Exception call()
            throws Exception
        {
            try
            {
                KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX",
                    BouncyCastleJsseProvider.PROVIDER_NAME);
    
                keyMgrFact.init(config.serverKeyStore, config.serverPassword);
    
                SSLContext serverContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
    
                serverContext.init(keyMgrFact.getKeyManagers(), null,
                    SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));
    
                SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
                SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(port);
    
                sSock.setEnabledCipherSuites(new String[]{ config.cipherSuite });
    
                latch.countDown();
    
                SSLSocket sslSock = (SSLSocket)sSock.accept();
                sslSock.setUseClientMode(false);
    
                TestProtocolUtil.doServerProtocol(sslSock, "World");
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
}
