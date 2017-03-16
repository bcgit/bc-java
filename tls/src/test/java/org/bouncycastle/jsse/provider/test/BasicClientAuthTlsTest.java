package org.bouncycastle.jsse.provider.test;

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

public class BasicClientAuthTlsTest
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
    private static final int PORT_NO = 9020;

    public static class ClientAuthClient
        implements TestProtocolUtil.BlockingCallable
    {
        private final KeyStore trustStore;
        private final KeyStore clientStore;
        private final char[] clientKeyPass;
        private final CountDownLatch latch;

        public ClientAuthClient(KeyStore clientStore, char[] clientKeyPass, X509Certificate trustAnchor)
            throws GeneralSecurityException, IOException
        {
            this.trustStore = KeyStore.getInstance("JKS");

            trustStore.load(null, null);

            trustStore.setCertificateEntry("server", trustAnchor);

            this.clientStore = clientStore;
            this.clientKeyPass = clientKeyPass;
            this.latch = new CountDownLatch(1);
        }

        public Exception call()
            throws Exception
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
                SSLSocket cSock = (SSLSocket)fact.createSocket(HOST, PORT_NO);
    
                SSLUtils.restrictKeyExchange(cSock, "ECDHE_ECDSA");
    
                SSLSession session = cSock.getSession();
    
                assertNotNull(session.getCipherSuite());
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

    public static class ClientAuthServer
        implements TestProtocolUtil.BlockingCallable
    {
        private final KeyStore serverStore;
        private final char[] keyPass;
        private final KeyStore trustStore;
        private final CountDownLatch latch;

        ClientAuthServer(KeyStore serverStore, char[] keyPass, X509Certificate trustAnchor)
            throws GeneralSecurityException, IOException
        {
            this.serverStore = serverStore;
            this.keyPass = keyPass;
            this.trustStore = KeyStore.getInstance("JKS");

            trustStore.load(null, null);

            trustStore.setCertificateEntry("client", trustAnchor);

            this.latch = new CountDownLatch(1);
        }

        public Exception call()
            throws Exception
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
                SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(PORT_NO);
    
                SSLUtils.enableAll(sSock);
    
                sSock.setNeedClientAuth(true);
    
                latch.countDown();
    
                SSLSocket sslSock = (SSLSocket)sSock.accept();
    
                SSLSession session = sslSock.getSession();
    
                assertNotNull(session.getCipherSuite());
                assertEquals("CN=Test CA Certificate", session.getLocalPrincipal().getName());
                assertEquals("CN=Test CA Certificate", session.getPeerPrincipal().getName());
    
                TestProtocolUtil.doServerProtocol(sslSock, "World");
    
                sslSock.close();
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

    public void testClientAuthTlsConnection()
        throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        KeyPair caKeyPair = TestUtils.generateECKeyPair();;

        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore serverKs = KeyStore.getInstance("JKS");

        serverKs.load(null, null);

        serverKs.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        KeyStore clientKs = KeyStore.getInstance("JKS");

        clientKs.load(null, null);

        clientKs.setKeyEntry("client", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        TestProtocolUtil.runClientAndServer(new ClientAuthServer(serverKs, keyPass, caCert), new ClientAuthClient(serverKs, keyPass, caCert));
    }
}
