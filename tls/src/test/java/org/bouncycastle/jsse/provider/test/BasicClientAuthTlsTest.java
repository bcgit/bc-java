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
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCJSSE") == null)
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

        public Object call()
            throws Exception
        {
            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("X509", "BCJSSE");

            trustMgrFact.init(trustStore);

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", "BCJSSE");

            keyMgrFact.init(clientStore, clientKeyPass);

            SSLContext clientContext = SSLContext.getInstance("TLS");

            clientContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), SecureRandom.getInstance("DEFAULT", "BC"));

            SSLSocketFactory fact = clientContext.getSocketFactory();
            SSLSocket cSock = (SSLSocket)fact.createSocket(HOST, PORT_NO);

            SSLUtils.restrictKeyExchange(cSock, "ECDHE_ECDSA");

            // TODO[jsse] Is this supposed to be a necessary call to get an SSL connection?
            cSock.startHandshake();

            TestProtocolUtil.doClientProtocol(cSock, "Hello");

            // TODO[jsse] Establish that server-auth actually worked - via session peer certificate?

            latch.countDown();

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

        public Object call()
            throws Exception
        {
            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("X509", "BCJSSE");

            keyMgrFact.init(serverStore, keyPass);

            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX", "BCJSSE");

            trustMgrFact.init(trustStore);

            SSLContext serverContext = SSLContext.getInstance("TLS");

            serverContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), SecureRandom.getInstance("DEFAULT", "BC"));

            SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
            SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(PORT_NO);

            sSock.setNeedClientAuth(true);

            latch.countDown();

            SSLSocket sslSock = (SSLSocket)sSock.accept();

            SSLUtils.restrictKeyExchange(sslSock, "ECDHE_ECDSA");

            // TODO[jsse] Is this supposed to be a necessary call to get an SSL connection?
            sslSock.startHandshake();

            TestProtocolUtil.doServerProtocol(sslSock, "World");

            // TODO[jsse] Establish that client-auth actually worked - via session peer certificate?

            sslSock.close();

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
