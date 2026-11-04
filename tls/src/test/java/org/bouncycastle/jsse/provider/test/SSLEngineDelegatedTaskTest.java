package org.bouncycastle.jsse.provider.test;

import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

import junit.framework.TestCase;

import org.bouncycastle.util.Strings;

/**
 * Tests of the SSLEngine delegated task mechanism: handshake steps are handed out as
 * {@link SSLEngine#getDelegatedTask()} runnables and run here on threads other than the one driving
 * wrap/unwrap, so a TrustManager or KeyManager callback must be seen on a task thread.
 */
public class SSLEngineDelegatedTaskTest
    extends TestCase
{
    private static final char[] PASSWORD = "password".toCharArray();

    private static final String[] PROPERTY_NAMES = { "org.bouncycastle.jsse.client.enableDelegatedTasks",
        "org.bouncycastle.jsse.server.enableDelegatedTasks" };

    private final String[] savedProperties = new String[PROPERTY_NAMES.length];

    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);

        for (int i = 0; i < PROPERTY_NAMES.length; ++i)
        {
            savedProperties[i] = System.getProperty(PROPERTY_NAMES[i]);
            System.setProperty(PROPERTY_NAMES[i], "true");
        }
    }

    protected void tearDown()
    {
        for (int i = 0; i < PROPERTY_NAMES.length; ++i)
        {
            if (null == savedProperties[i])
            {
                System.getProperties().remove(PROPERTY_NAMES[i]);
            }
            else
            {
                System.setProperty(PROPERTY_NAMES[i], savedProperties[i]);
            }
        }
    }

    public void testDisabledByDefault() throws Exception
    {
        for (int i = 0; i < PROPERTY_NAMES.length; ++i)
        {
            System.getProperties().remove(PROPERTY_NAMES[i]);
        }

        Fixture fixture = new Fixture();
        SSLEngine clientEngine = fixture.createClientEngine("TLSv1.3", false);
        SSLEngine serverEngine = fixture.createServerEngine("TLSv1.3", false);

        clientEngine.beginHandshake();
        assertEquals(HandshakeStatus.NEED_WRAP, clientEngine.getHandshakeStatus());
        assertNull(clientEngine.getDelegatedTask());

        Harness harness = new Harness(clientEngine, serverEngine);
        harness.run();

        assertEquals(0, harness.clientTasks.count);
        assertEquals(0, harness.serverTasks.count);
        assertEquals(1, harness.clientFinished);
        assertEquals(1, harness.serverFinished);
        assertSame(Thread.currentThread(), fixture.clientTrustManager.checkServerTrustedThread);
    }

    public void testTLSv13() throws Exception
    {
        runHandshake("TLSv1.3", false);
    }

    public void testTLSv13ClientAuth() throws Exception
    {
        runHandshake("TLSv1.3", true);
    }

    public void testTLSv12() throws Exception
    {
        runHandshake("TLSv1.2", false);
    }

    public void testTLSv12ClientAuth() throws Exception
    {
        runHandshake("TLSv1.2", true);
    }

    public void testClientHelloDeferred() throws Exception
    {
        Fixture fixture = new Fixture();
        SSLEngine clientEngine = fixture.createClientEngine("TLSv1.3", false);

        clientEngine.beginHandshake();
        assertEquals(HandshakeStatus.NEED_TASK, clientEngine.getHandshakeStatus());

        // Nothing to wrap until the ClientHello has been produced by the task
        ByteBuffer clientToServer = ByteBuffer.allocate(clientEngine.getSession().getPacketBufferSize());
        SSLEngineResult result = clientEngine.wrap(ByteBuffer.allocate(0), clientToServer);
        assertEquals(Status.OK, result.getStatus());
        assertEquals(HandshakeStatus.NEED_TASK, result.getHandshakeStatus());
        assertEquals(0, result.bytesProduced());

        TaskRunner taskRunner = new TaskRunner();
        assertEquals(1, taskRunner.runTasks(clientEngine));
        assertEquals(HandshakeStatus.NEED_WRAP, clientEngine.getHandshakeStatus());

        result = clientEngine.wrap(ByteBuffer.allocate(0), clientToServer);
        assertEquals(HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());
        assertTrue(result.bytesProduced() > 0);
    }

    public void testTaskHandedOutOnce() throws Exception
    {
        Fixture fixture = new Fixture();
        SSLEngine clientEngine = fixture.createClientEngine("TLSv1.3", false);

        clientEngine.beginHandshake();

        Runnable task = clientEngine.getDelegatedTask();
        assertNotNull(task);
        assertNull(clientEngine.getDelegatedTask());
        assertEquals(HandshakeStatus.NEED_TASK, clientEngine.getHandshakeStatus());

        task.run();
        assertNull(clientEngine.getDelegatedTask());
        assertEquals(HandshakeStatus.NEED_WRAP, clientEngine.getHandshakeStatus());

        // Running a task again is a no-op: the step is not repeated and no failure is recorded
        task.run();
        assertNull(clientEngine.getDelegatedTask());
        assertEquals(HandshakeStatus.NEED_WRAP, clientEngine.getHandshakeStatus());
        SSLEngineResult result = clientEngine.wrap(ByteBuffer.allocate(0),
            ByteBuffer.allocate(clientEngine.getSession().getPacketBufferSize()));
        assertEquals(Status.OK, result.getStatus());
        assertTrue(result.bytesProduced() > 0);
    }

    public void testInputRefusedWhileTaskPending() throws Exception
    {
        Fixture fixture = new Fixture();
        SSLEngine clientEngine = fixture.createClientEngine("TLSv1.3", false);
        SSLEngine serverEngine = fixture.createServerEngine("TLSv1.3", false);

        TaskRunner taskRunner = new TaskRunner();

        clientEngine.beginHandshake();
        taskRunner.runTasks(clientEngine);

        ByteBuffer clientToServer = ByteBuffer.allocate(clientEngine.getSession().getPacketBufferSize());
        clientEngine.wrap(ByteBuffer.allocate(0), clientToServer);
        clientToServer.flip();

        // Append a second (bogus) record behind the ClientHello; it must not be touched while the task is pending
        int clientHelloLength = clientToServer.remaining();
        ByteBuffer bogusRecord = ByteBuffer.wrap(new byte[]{ 22, 3, 3, 0, 1, 0 });
        ByteBuffer input = ByteBuffer.allocate(clientHelloLength + bogusRecord.remaining());
        input.put(clientToServer);
        input.put(bogusRecord);
        input.flip();

        ByteBuffer serverIn = ByteBuffer.allocate(serverEngine.getSession().getApplicationBufferSize());

        SSLEngineResult result = serverEngine.unwrap(input, serverIn);
        assertEquals(Status.OK, result.getStatus());
        assertEquals(HandshakeStatus.NEED_TASK, result.getHandshakeStatus());
        assertEquals(clientHelloLength, result.bytesConsumed());

        result = serverEngine.unwrap(input, serverIn);
        assertEquals(Status.OK, result.getStatus());
        assertEquals(HandshakeStatus.NEED_TASK, result.getHandshakeStatus());
        assertEquals(0, result.bytesConsumed());
        assertEquals(clientHelloLength, input.position());

        assertEquals(1, taskRunner.runTasks(serverEngine));
        assertEquals(HandshakeStatus.NEED_WRAP, serverEngine.getHandshakeStatus());
    }

    public void testTrustFailureReportedFromWrap() throws Exception
    {
        Fixture fixture = new Fixture();
        fixture.clientTrustManager.rejectServer = true;

        SSLEngine clientEngine = fixture.createClientEngine("TLSv1.3", false);
        SSLEngine serverEngine = fixture.createServerEngine("TLSv1.3", false);

        Harness harness = new Harness(clientEngine, serverEngine);
        try
        {
            harness.run();
            fail("expected the client to fail the handshake");
        }
        catch (SSLException e)
        {
            // The failure came from a task; it is reported from wrap()
            assertSame(clientEngine, harness.failedEngine);
            assertTrue(harness.failedInWrap);
        }

        assertTrue("TrustManager ran on a task thread", harness.clientTasks.ranOnTaskThread(
            fixture.clientTrustManager.checkServerTrustedThread));

        // The alert raised by the failure is still to be flushed, then the server sees it as a fatal alert
        ByteBuffer clientToServer = ByteBuffer.allocate(clientEngine.getSession().getPacketBufferSize());
        SSLEngineResult result = clientEngine.wrap(ByteBuffer.allocate(0), clientToServer);
        assertTrue(result.bytesProduced() > 0);
        assertTrue(clientEngine.isOutboundDone());

        clientToServer.flip();
        try
        {
            SSLEngineResult serverResult = serverEngine.unwrap(clientToServer,
                ByteBuffer.allocate(serverEngine.getSession().getApplicationBufferSize()));

            // An unwrap failure during the handshake is itself reported from the next wrap (see ProvSSLEngine)
            assertEquals(HandshakeStatus.NEED_WRAP, serverResult.getHandshakeStatus());
            serverEngine.wrap(ByteBuffer.allocate(0), ByteBuffer.allocate(serverEngine.getSession().getPacketBufferSize()));

            fail("expected the server to see a fatal alert");
        }
        catch (SSLException e)
        {
            // expected
        }
    }

    private void runHandshake(String protocol, boolean clientAuth) throws Exception
    {
        Fixture fixture = new Fixture();

        SSLEngine clientEngine = fixture.createClientEngine(protocol, clientAuth);
        SSLEngine serverEngine = fixture.createServerEngine(protocol, clientAuth);

        Harness harness = new Harness(clientEngine, serverEngine);
        harness.run();

        assertEquals("client FINISHED", 1, harness.clientFinished);
        assertEquals("server FINISHED", 1, harness.serverFinished);

        // Client: at least the ClientHello and the server's flight; server: at least ClientHello and Finished
        assertTrue("client tasks: " + harness.clientTasks.count, harness.clientTasks.count >= 2);
        assertTrue("server tasks: " + harness.serverTasks.count, harness.serverTasks.count >= 2);

        assertTrue("checkServerTrusted on a task thread",
            harness.clientTasks.ranOnTaskThread(fixture.clientTrustManager.checkServerTrustedThread));
        assertTrue("chooseEngineServerAlias on a task thread",
            harness.serverTasks.ranOnTaskThread(fixture.serverKeyManager.chooseEngineServerAliasThread));

        if (clientAuth)
        {
            assertTrue("checkClientTrusted on a task thread",
                harness.serverTasks.ranOnTaskThread(fixture.serverTrustManager.checkClientTrustedThread));
            assertTrue("chooseEngineClientAlias on a task thread",
                harness.clientTasks.ranOnTaskThread(fixture.clientKeyManager.chooseEngineClientAliasThread));
            assertNotNull(serverEngine.getSession().getPeerCertificates());
        }
        else
        {
            assertNull(fixture.serverTrustManager.checkClientTrustedThread);
            assertNull(fixture.clientKeyManager.chooseEngineClientAliasThread);
        }
    }

    /**
     * Runs each delegated task on a fresh thread, recording the threads used.
     */
    private static class TaskRunner
    {
        final Set<Thread> threads = ConcurrentHashMap.newKeySet();
        int count = 0;

        int runTasks(SSLEngine engine) throws InterruptedException
        {
            int runCount = 0;

            Runnable task;
            while ((task = engine.getDelegatedTask()) != null)
            {
                Thread thread = new Thread(task, "delegated-task-" + count);
                threads.add(thread);
                thread.start();
                thread.join();

                ++count;
                ++runCount;
            }

            assertTrue(HandshakeStatus.NEED_TASK != engine.getHandshakeStatus());

            return runCount;
        }

        boolean ranOnTaskThread(Thread thread)
        {
            return null != thread && threads.contains(thread);
        }
    }

    /**
     * Drives a client and server engine through a handshake and a data exchange, running delegated tasks
     * through a {@link TaskRunner} for each.
     */
    private static class Harness
    {
        final SSLEngine clientEngine, serverEngine;
        final TaskRunner clientTasks = new TaskRunner(), serverTasks = new TaskRunner();
        int clientFinished = 0, serverFinished = 0;
        SSLEngine failedEngine = null;
        boolean failedInWrap = false;

        Harness(SSLEngine clientEngine, SSLEngine serverEngine)
        {
            this.clientEngine = clientEngine;
            this.serverEngine = serverEngine;
        }

        void run() throws Exception
        {
            ByteBuffer clientIn = ByteBuffer.allocate(clientEngine.getSession().getApplicationBufferSize() + 64);
            ByteBuffer serverIn = ByteBuffer.allocate(serverEngine.getSession().getApplicationBufferSize() + 64);
            ByteBuffer clientToServer = ByteBuffer.allocate(clientEngine.getSession().getPacketBufferSize());
            ByteBuffer serverToClient = ByteBuffer.allocate(serverEngine.getSession().getPacketBufferSize());

            ByteBuffer clientOut = ByteBuffer.wrap(Strings.toUTF8ByteArray("Dear Prudence, won't you come out to play?"));
            ByteBuffer serverOut = ByteBuffer.wrap(Strings.toUTF8ByteArray("Impudence! I won't come out to today."));

            boolean dataDone = false;
            while (!isEngineClosed(clientEngine) || !isEngineClosed(serverEngine))
            {
                step(clientEngine, clientTasks, true, clientOut, clientToServer);
                step(serverEngine, serverTasks, true, serverOut, serverToClient);

                ((java.nio.Buffer)clientToServer).flip();
                ((java.nio.Buffer)serverToClient).flip();

                step(clientEngine, clientTasks, false, serverToClient, clientIn);
                step(serverEngine, serverTasks, false, clientToServer, serverIn);

                clientToServer.compact();
                serverToClient.compact();

                if (!dataDone && (clientOut.limit() == serverIn.position()) && (serverOut.limit() == clientIn.position()))
                {
                    checkData(clientOut, serverIn);
                    checkData(serverOut, clientIn);

                    clientEngine.closeOutbound();

                    dataDone = true;
                }
            }

            assertTrue(dataDone);
        }

        private void step(SSLEngine engine, TaskRunner tasks, boolean wrap, ByteBuffer src, ByteBuffer dst)
            throws Exception
        {
            SSLEngineResult result;
            try
            {
                result = wrap ? engine.wrap(src, dst) : engine.unwrap(src, dst);
            }
            catch (SSLException e)
            {
                this.failedEngine = engine;
                this.failedInWrap = wrap;
                throw e;
            }

            if (HandshakeStatus.FINISHED == result.getHandshakeStatus())
            {
                if (engine == clientEngine)
                {
                    ++clientFinished;
                }
                else
                {
                    ++serverFinished;
                }
            }

            checkFinishedBeforeNotHandshaking(engine, result.getHandshakeStatus(), wrap ? "wrap result" : "unwrap result");

            if (HandshakeStatus.NEED_TASK == result.getHandshakeStatus())
            {
                // While a task is pending the engine must not have consumed any further input
                tasks.runTasks(engine);
            }

            checkFinishedBeforeNotHandshaking(engine, engine.getHandshakeStatus(), wrap ? "after wrap" : "after unwrap");
        }

        /*
         * Once the handshake has begun, FINISHED must be returned (from wrap/unwrap) before the engine
         * reports NOT_HANDSHAKING. In particular a delegated task that completes the handshake must leave
         * the engine requesting the wrap/unwrap that will report FINISHED.
         */
        private void checkFinishedBeforeNotHandshaking(SSLEngine engine, HandshakeStatus handshakeStatus, String where)
        {
            if (HandshakeStatus.NOT_HANDSHAKING == handshakeStatus && !isEngineClosed(engine))
            {
                int finished = (engine == clientEngine) ? clientFinished : serverFinished;
                assertTrue("NOT_HANDSHAKING before FINISHED (" + (engine.getUseClientMode() ? "client" : "server")
                    + ", " + where + ")", finished > 0);
            }
        }

        private static void checkData(ByteBuffer a, ByteBuffer b)
        {
            ((java.nio.Buffer)a).flip();
            ((java.nio.Buffer)b).flip();

            assertEquals(a, b);

            ((java.nio.Buffer)a).position(a.limit());
            ((java.nio.Buffer)b).position(b.limit());
            ((java.nio.Buffer)a).limit(a.capacity());
            ((java.nio.Buffer)b).limit(b.capacity());
        }

        private static boolean isEngineClosed(SSLEngine engine)
        {
            return engine.isOutboundDone() && engine.isInboundDone();
        }
    }

    /**
     * Key material and the recording managers for one client/server pair.
     */
    private static class Fixture
    {
        final RecordingTrustManager clientTrustManager, serverTrustManager;
        final RecordingKeyManager clientKeyManager, serverKeyManager;

        Fixture() throws Exception
        {
            KeyPair caKeyPair = TestUtils.generateECKeyPair();
            X509Certificate caCert = TestUtils.generateRootCert(caKeyPair);

            KeyStore ts = KeyStore.getInstance("JKS");
            ts.load(null, null);
            ts.setCertificateEntry("ca", caCert);

            KeyStore serverKs = KeyStore.getInstance("JKS");
            serverKs.load(null, null);
            serverKs.setKeyEntry("server", caKeyPair.getPrivate(), PASSWORD, new X509Certificate[]{ caCert });

            KeyStore clientKs = KeyStore.getInstance("JKS");
            clientKs.load(null, null);
            clientKs.setKeyEntry("client", caKeyPair.getPrivate(), PASSWORD, new X509Certificate[]{ caCert });

            this.clientTrustManager = new RecordingTrustManager(createTrustManager(ts));
            this.serverTrustManager = new RecordingTrustManager(createTrustManager(ts));
            this.clientKeyManager = new RecordingKeyManager(createKeyManager(clientKs));
            this.serverKeyManager = new RecordingKeyManager(createKeyManager(serverKs));
        }

        SSLEngine createClientEngine(String protocol, boolean clientAuth) throws Exception
        {
            SSLContext context = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
            context.init(clientAuth ? new KeyManager[]{ clientKeyManager } : null,
                new TrustManager[]{ clientTrustManager }, null);

            SSLEngine engine = context.createSSLEngine();
            engine.setEnabledProtocols(new String[]{ protocol });
            engine.setUseClientMode(true);
            return engine;
        }

        SSLEngine createServerEngine(String protocol, boolean clientAuth) throws Exception
        {
            SSLContext context = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
            context.init(new KeyManager[]{ serverKeyManager }, new TrustManager[]{ serverTrustManager }, null);

            SSLEngine engine = context.createSSLEngine();
            engine.setEnabledProtocols(new String[]{ protocol });
            engine.setUseClientMode(false);
            engine.setNeedClientAuth(clientAuth);
            return engine;
        }

        private static X509ExtendedTrustManager createTrustManager(KeyStore ts) throws Exception
        {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);
            tmf.init(ts);
            return (X509ExtendedTrustManager)tmf.getTrustManagers()[0];
        }

        private static X509ExtendedKeyManager createKeyManager(KeyStore ks) throws Exception
        {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);
            kmf.init(ks, PASSWORD);
            return (X509ExtendedKeyManager)kmf.getKeyManagers()[0];
        }
    }

    private static class RecordingTrustManager
        extends X509ExtendedTrustManager
    {
        private final X509ExtendedTrustManager delegate;

        volatile Thread checkClientTrustedThread = null;
        volatile Thread checkServerTrustedThread = null;
        volatile boolean rejectServer = false;

        RecordingTrustManager(X509ExtendedTrustManager delegate)
        {
            this.delegate = delegate;
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException
        {
            this.checkClientTrustedThread = Thread.currentThread();
            delegate.checkClientTrusted(chain, authType);
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException
        {
            this.checkClientTrustedThread = Thread.currentThread();
            delegate.checkClientTrusted(chain, authType, socket);
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException
        {
            this.checkClientTrustedThread = Thread.currentThread();
            delegate.checkClientTrusted(chain, authType, engine);
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
        {
            this.checkServerTrustedThread = Thread.currentThread();
            checkRejectServer();
            delegate.checkServerTrusted(chain, authType);
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException
        {
            this.checkServerTrustedThread = Thread.currentThread();
            checkRejectServer();
            delegate.checkServerTrusted(chain, authType, socket);
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException
        {
            this.checkServerTrustedThread = Thread.currentThread();
            checkRejectServer();
            delegate.checkServerTrusted(chain, authType, engine);
        }

        public X509Certificate[] getAcceptedIssuers()
        {
            return delegate.getAcceptedIssuers();
        }

        private void checkRejectServer() throws CertificateException
        {
            if (rejectServer)
            {
                throw new CertificateException("rejected by test");
            }
        }
    }

    private static class RecordingKeyManager
        extends X509ExtendedKeyManager
    {
        private final X509ExtendedKeyManager delegate;

        volatile Thread chooseEngineClientAliasThread = null;
        volatile Thread chooseEngineServerAliasThread = null;

        RecordingKeyManager(X509ExtendedKeyManager delegate)
        {
            this.delegate = delegate;
        }

        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket)
        {
            return delegate.chooseClientAlias(keyType, issuers, socket);
        }

        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine)
        {
            this.chooseEngineClientAliasThread = Thread.currentThread();
            return delegate.chooseEngineClientAlias(keyType, issuers, engine);
        }

        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine)
        {
            this.chooseEngineServerAliasThread = Thread.currentThread();
            return delegate.chooseEngineServerAlias(keyType, issuers, engine);
        }

        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
        {
            return delegate.chooseServerAlias(keyType, issuers, socket);
        }

        public X509Certificate[] getCertificateChain(String alias)
        {
            return delegate.getCertificateChain(alias);
        }

        public String[] getClientAliases(String keyType, Principal[] issuers)
        {
            return delegate.getClientAliases(keyType, issuers);
        }

        public PrivateKey getPrivateKey(String alias)
        {
            return delegate.getPrivateKey(alias);
        }

        public String[] getServerAliases(String keyType, Principal[] issuers)
        {
            return delegate.getServerAliases(keyType, issuers);
        }
    }
}
