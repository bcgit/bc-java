package org.bouncycastle.jsse.provider.test;

import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import junit.framework.TestCase;

public class BasicTlsTest
    extends TestCase
{
    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    private static final String HOST = "localhost";
    private static final int PORT_NO = 9021;

    public static class SimpleClient
        implements TestProtocolUtil.BlockingCallable
    {
        private final boolean layered;
        private final KeyStore trustStore;
        private final CountDownLatch latch;

        public SimpleClient(boolean layered, KeyStore trustStore)
        {
            this.layered = layered;
            this.trustStore = trustStore;
            this.latch = new CountDownLatch(1);
        }

        public Exception call()
            throws Exception
        {
            try
            {
                TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX",
                    ProviderUtils.PROVIDER_NAME_BCJSSE);
                trustMgrFact.init(trustStore);

                SSLContext clientContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
                clientContext.init(null, trustMgrFact.getTrustManagers(),
                    SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

//                TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
//                trustMgrFact.init(trustStore);
//    
//                SSLContext clientContext = SSLContext.getInstance("TLS", "SunJSSE");
//                clientContext.init(null, trustMgrFact.getTrustManagers(), null);


                SSLSocketFactory fact = clientContext.getSocketFactory();

                SSLSocket cSock;
                if (layered)
                {
                    Socket s = SocketFactory.getDefault().createSocket(HOST, PORT_NO);
                    cSock = (SSLSocket)fact.createSocket(s, HOST, PORT_NO, true);
                }
                else
                {
                    cSock = (SSLSocket)fact.createSocket(HOST, PORT_NO);
                }

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

    public static class SimpleServer
        implements TestProtocolUtil.BlockingCallable
    {
        private final KeyStore serverStore;
        private final char[] keyPass;
        private final CountDownLatch latch;

        SimpleServer(KeyStore serverStore, char[] keyPass)
        {
            this.serverStore = serverStore;
            this.keyPass = keyPass;
            this.latch = new CountDownLatch(1);
        }

        public Exception call()
            throws Exception
        {
            try
            {
                KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX",
                    ProviderUtils.PROVIDER_NAME_BCJSSE);
                keyMgrFact.init(serverStore, keyPass);

                SSLContext serverContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
                serverContext.init(keyMgrFact.getKeyManagers(), null,
                    SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

//                KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", "SunJSSE");
//                keyMgrFact.init(serverStore, keyPass);
//
//                SSLContext serverContext = SSLContext.getInstance("TLS", "SunJSSE");
//                serverContext.init(keyMgrFact.getKeyManagers(), null, null);


                SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
                SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(PORT_NO);

                SSLUtils.enableAll(sSock);

                latch.countDown();

                SSLSocket sslSock = (SSLSocket)sSock.accept();
                sslSock.setUseClientMode(false);

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

        public void await()
            throws InterruptedException
        {
            latch.await();
        }
    }

    public void testBasicTlsConnection()
        throws Exception
    {
        runTestBasicTlsConnection(false);
    }

    public void testBasicTlsConnectionLayered()
        throws Exception
    {
        runTestBasicTlsConnection(true);
    }

    public void testNullRandomJsseInit()
        throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        KeyPair caKeyPair = TestUtils.generateECKeyPair();

        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        KeyStore ts = KeyStore.getInstance("JKS");
        ts.load(null, null);
        ts.setCertificateEntry("ca", caCert);

        TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX",
            ProviderUtils.PROVIDER_NAME_BCJSSE);

        trustMgrFact.init(ts);

        SSLContext clientContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);

        clientContext.init(null, trustMgrFact.getTrustManagers(), null);
    }

    protected void runTestBasicTlsConnection(boolean layered)
        throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        KeyPair caKeyPairDSA = TestUtils.generateDSAKeyPair();
        KeyPair caKeyPairEC = TestUtils.generateECKeyPair();
        KeyPair caKeyPairRSA = TestUtils.generateRSAKeyPair();

        X509Certificate caCertDSA = TestUtils.generateRootCert(caKeyPairDSA);
        X509Certificate caCertEC = TestUtils.generateRootCert(caKeyPairEC);
        X509Certificate caCertRSA = TestUtils.generateRootCert(caKeyPairRSA);

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("serverDSA", caKeyPairDSA.getPrivate(), keyPass, new X509Certificate[]{ caCertDSA });
        ks.setKeyEntry("serverEC", caKeyPairEC.getPrivate(), keyPass, new X509Certificate[]{ caCertEC });
        ks.setKeyEntry("serverRSA", caKeyPairRSA.getPrivate(), keyPass, new X509Certificate[]{ caCertRSA });

        KeyStore ts = KeyStore.getInstance("JKS");
        ts.load(null, null);
        ts.setCertificateEntry("caDSA", caCertDSA);
        ts.setCertificateEntry("caEC", caCertEC);
        ts.setCertificateEntry("caRSA", caCertRSA);

        TestProtocolUtil.runClientAndServer(new SimpleServer(ks, keyPass), new SimpleClient(layered, ts));
    }
}
