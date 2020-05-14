package org.bouncycastle.jsse.provider.test;

import static org.junit.Assert.assertNotEquals;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.junit.Assert;

import junit.framework.TestCase;

public class BasicClientAuthTlsTest
    extends TestCase
{
    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    private static final String HOST = "localhost";
    private static final int PORT_NO_ACCEPTED = 9019;
    private static final int PORT_NO_REJECTED = 9020;

    public static class ClientAuthAcceptedClient
        implements TestProtocolUtil.BlockingCallable
    {
        private final KeyStore trustStore;
        private final KeyStore clientStore;
        private final char[] clientKeyPass;
        private final CountDownLatch latch;

        public ClientAuthAcceptedClient(KeyStore clientStore, char[] clientKeyPass, X509Certificate trustAnchor)
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
                    ProviderUtils.PROVIDER_NAME_BCJSSE);
    
                trustMgrFact.init(trustStore);
    
                KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX",
                    ProviderUtils.PROVIDER_NAME_BCJSSE);
    
                keyMgrFact.init(clientStore, clientKeyPass);
    
                SSLContext clientContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
    
                clientContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(),
                    SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));
    
                SSLSocketFactory fact = clientContext.getSocketFactory();
                SSLSocket cSock = (SSLSocket)fact.createSocket(HOST, PORT_NO_ACCEPTED);

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

    public static class ClientAuthRejectedClient
        implements TestProtocolUtil.BlockingCallable
    {
        private final KeyStore trustStore;
        private final CountDownLatch latch;

        public ClientAuthRejectedClient(X509Certificate trustAnchor)
            throws GeneralSecurityException, IOException
        {
            this.trustStore = KeyStore.getInstance("JKS");
            trustStore.load(null, null);
            trustStore.setCertificateEntry("server", trustAnchor);

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

                SSLSocketFactory fact = clientContext.getSocketFactory();
                SSLSocket cSock = (SSLSocket)fact.createSocket(HOST, PORT_NO_REJECTED);

                SSLSession session = cSock.getSession();
                assertNotNull(session);
                assertNotEquals("SSL_NULL_WITH_NULL_NULL", session.getCipherSuite());
                assertNull(session.getLocalPrincipal());
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
        private final int port;
        private final boolean needClientAuth;
        private final KeyStore serverStore;
        private final char[] keyPass;
        private final KeyStore trustStore;
        private final CountDownLatch latch;

        ClientAuthServer(int port, boolean needClientAuth, KeyStore serverStore, char[] keyPass,
            X509Certificate trustAnchor) throws GeneralSecurityException, IOException
        {
            this.port = port;
            this.needClientAuth = needClientAuth;
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
    
                if (needClientAuth)
                {
                    sSock.setNeedClientAuth(true);
                }
                else
                {
                    sSock.setWantClientAuth(true);
                }

                latch.countDown();
    
                SSLSocket sslSock = (SSLSocket)sSock.accept();
    
                SSLSession session = sslSock.getSession();
                assertNotNull(session);
                assertNotEquals("SSL_NULL_WITH_NULL_NULL", session.getCipherSuite());
                assertEquals("CN=Test CA Certificate", session.getLocalPrincipal().getName());

                if (needClientAuth)
                {
                    assertEquals("CN=Test CA Certificate", session.getPeerPrincipal().getName());
                }
                else
                {
                    try
                    {
                        session.getPeerPrincipal();
                        Assert.fail();
                    }
                    catch (SSLPeerUnverifiedException e)
                    {
                    }
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

        public void await()
            throws InterruptedException
        {
            latch.await();
        }
    }

    public void testClientAuthAccepted()
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

        TestProtocolUtil.runClientAndServer(new ClientAuthServer(PORT_NO_ACCEPTED, true, serverKs, keyPass, caCert),
            new ClientAuthAcceptedClient(clientKs, keyPass, caCert));
    }

    public void testClientAuthRejected()
        throws Exception
    {
        char[] keyPass = "keyPassword".toCharArray();

        KeyPair caKeyPair = TestUtils.generateECKeyPair();;
        X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

        KeyStore serverKs = KeyStore.getInstance("JKS");
        serverKs.load(null, null);
        serverKs.setKeyEntry("server", caKeyPair.getPrivate(), keyPass, new X509Certificate[]{ caCert });

        TestProtocolUtil.runClientAndServer(new ClientAuthServer(PORT_NO_REJECTED, false, serverKs, keyPass, caCert),
            new ClientAuthRejectedClient(caCert));
    }
}
