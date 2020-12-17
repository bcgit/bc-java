package org.bouncycastle.jsse.provider.test;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import junit.framework.TestCase;

public class CipherSuitesEngineTestCase extends TestCase
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

    public CipherSuitesEngineTestCase(String name)
    {
        super(name);

        this.config = null;
    }

    public CipherSuitesEngineTestCase(CipherSuitesTestConfig config)
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

        runTestConnection();
        runTestConnection();
    }

    private void runTestConnection() throws Throwable
    {
        SSLContext clientContext = createSSLContextClient();
        SSLContext serverContext = createSSLContextServer();

        SSLEngine clientEngine = clientContext.createSSLEngine();
        clientEngine.setEnabledCipherSuites(new String[]{ config.cipherSuite });
        clientEngine.setEnabledProtocols(new String[]{ config.protocol });
        clientEngine.setUseClientMode(true);

        SSLEngine serverEngine = serverContext.createSSLEngine();
        serverEngine.setEnabledCipherSuites(new String[]{ config.cipherSuite });
        serverEngine.setEnabledProtocols(new String[]{ config.protocol });
        serverEngine.setUseClientMode(false);
        serverEngine.setWantClientAuth(false);

        SSLSession clientSession = clientEngine.getSession();
        SSLSession serverSession = serverEngine.getSession();

        final int clientAppBufSize = clientSession.getApplicationBufferSize();
        final int serverAppBufSize = serverSession.getApplicationBufferSize();

        final int clientNetBufSize = clientSession.getPacketBufferSize();
        final int serverNetBufSize = serverSession.getPacketBufferSize();

        ByteBuffer clientIn = ByteBuffer.allocate(clientAppBufSize + 64);
        ByteBuffer serverIn = ByteBuffer.allocate(serverAppBufSize + 64);

        ByteBuffer clientToServer = ByteBuffer.allocate(clientNetBufSize);
        ByteBuffer serverToClient = ByteBuffer.allocate(serverNetBufSize);

        ByteBuffer clientOut = ByteBuffer.wrap("Dear Prudence, won't you come out to play?".getBytes("UTF-8"));
        ByteBuffer serverOut = ByteBuffer.wrap("Impudence! I won't come out to today.".getBytes("UTF-8"));

        SSLEngineResult clientResult;
        SSLEngineResult serverResult;

        boolean dataDone = false;
        while (!isEngineClosed(clientEngine) || !isEngineClosed(serverEngine))
        {
            clientResult = clientEngine.wrap(clientOut, clientToServer);
            runDelegatedTasks(clientEngine, clientResult);

            serverResult = serverEngine.wrap(serverOut, serverToClient);
            runDelegatedTasks(serverEngine, serverResult);

            clientToServer.flip();
            serverToClient.flip();

            clientResult = clientEngine.unwrap(serverToClient, clientIn);
            runDelegatedTasks(clientEngine, clientResult);

            serverResult = serverEngine.unwrap(clientToServer, serverIn);
            runDelegatedTasks(serverEngine, serverResult);

            clientToServer.compact();
            serverToClient.compact();

            if (!dataDone && (clientOut.limit() == serverIn.position()) && (serverOut.limit() == clientIn.position()))
            {
                checkData(clientOut, serverIn);
                checkData(serverOut, clientIn);

                clientEngine.closeOutbound();
                // engineServer.closeOutbound();

                dataDone = true;
            }
        }
    }

    private static void checkData(ByteBuffer a, ByteBuffer b) throws Exception
    {
        a.flip();
        b.flip();

        assertEquals(a, b);

        a.position(a.limit());
        b.position(b.limit());
        a.limit(a.capacity());
        b.limit(b.capacity());
    }

    private SSLContext createSSLContextClient() throws GeneralSecurityException
    {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);
        tmf.init(config.clientTrustStore);

        SecureRandom random = SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC);

        SSLContext clientContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
        clientContext.init(null, tmf.getTrustManagers(), random);
        return clientContext;
    }

    private SSLContext createSSLContextServer() throws GeneralSecurityException
    {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);
        kmf.init(config.serverKeyStore, config.serverPassword);

        SecureRandom random = SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC);

        SSLContext serverContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
        serverContext.init(kmf.getKeyManagers(), null, random);
        return serverContext;
    }

    private static boolean isEngineClosed(SSLEngine engine)
    {
        return (engine.isOutboundDone() && engine.isInboundDone());
    }

    private static void runDelegatedTasks(SSLEngine engine, SSLEngineResult result)
    {
        if (HandshakeStatus.NEED_TASK != result.getHandshakeStatus())
        {
            return;
        }

        Runnable runnable;
        while ((runnable = engine.getDelegatedTask()) != null)
        {
            runnable.run();
        }

        assertTrue(HandshakeStatus.NEED_TASK != engine.getHandshakeStatus());
    }
}
