package org.bouncycastle.tls.test;

import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.Security;
import java.util.List;

import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.keylog.TlsKeyLogLabel;
import org.bouncycastle.tls.keylog.test.RecordingTlsKeyLog;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import junit.framework.TestCase;

/**
 * Checks that a handshake reports the secrets RFC 9850 says it should, and nothing else.
 * <p>
 * Both ends of each handshake run here, so every secret is derived twice, independently, and lands
 * in the log twice. That the two copies agree is what makes this a test of the values and not just
 * of the plumbing: a secret captured from the wrong point in the key schedule would still be the
 * right length and still be logged, but the two sides would not have arrived at the same one.
 * <p>
 * Lives in <code>org.bouncycastle.tls.test</code> to reach the package-private mock peers the tls
 * test tree already provides; the fork's build copies that tree in alongside this class.
 */
public class TlsKeyLogTest
    extends TestCase
{
    /*
     * Has to be in place before KeyLog resolves it, which it does once, on the first secret of the
     * first handshake in the JVM. The literal is the documented property name; KeyLog's own
     * constant for it is package-private to org.bouncycastle.tls.
     */
    static
    {
        Security.setProperty("org.bouncycastle.tls.keylog.class", RecordingTlsKeyLog.class.getName());
    }

    private static final int CIPHER_SUITE_12 = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    private static final int CIPHER_SUITE_13 = CipherSuite.TLS_AES_128_GCM_SHA256;

    private static final String[] TLS13_LABELS = new String[]{
        TlsKeyLogLabel.CLIENT_HANDSHAKE_TRAFFIC_SECRET,
        TlsKeyLogLabel.SERVER_HANDSHAKE_TRAFFIC_SECRET,
        TlsKeyLogLabel.CLIENT_TRAFFIC_SECRET_0,
        TlsKeyLogLabel.SERVER_TRAFFIC_SECRET_0,
        TlsKeyLogLabel.EXPORTER_SECRET };

    public void testTLSv13() throws Exception
    {
        RecordingTlsKeyLog.reset();

        KeyLogTlsClient client = new KeyLogTlsClient(ProtocolVersion.TLSv13, CIPHER_SUITE_13, null);
        connect(client, new KeyLogTlsServer(ProtocolVersion.TLSv13, CIPHER_SUITE_13));

        byte[] clientRandom = client.getClientRandom();

        for (int i = 0; i < TLS13_LABELS.length; ++i)
        {
            String label = TLS13_LABELS[i];

            byte[] secret = assertLoggedByBothPeers(label, clientRandom);

            // TLS_AES_128_GCM_SHA256 puts SHA-256 in the key schedule, so every secret it derives
            // is 32 bytes (RFC 8446 7.1).
            assertEquals(label + " length", 32, secret.length);
        }

        // RFC 9850 2.2's master secret belongs to TLS 1.2 and earlier; 1.3 has no such record.
        assertEquals("CLIENT_RANDOM logged for TLS 1.3", 0,
            RecordingTlsKeyLog.getEntries(TlsKeyLogLabel.CLIENT_RANDOM).size());

        // Early data is not implemented, so nothing should have reached the early labels.
        assertEquals(0, RecordingTlsKeyLog.getEntries(TlsKeyLogLabel.CLIENT_EARLY_TRAFFIC_SECRET).size());
        assertEquals(0, RecordingTlsKeyLog.getEntries(TlsKeyLogLabel.EARLY_EXPORTER_SECRET).size());

        // Five labels, twice each, and no stray records from the rest of the key schedule
        // ("derived", "res master", the binder and Finished keys are all unreported).
        assertEquals("unexpected records", TLS13_LABELS.length * 2, RecordingTlsKeyLog.getEntries().size());
    }

    public void testTLSv12() throws Exception
    {
        RecordingTlsKeyLog.reset();

        KeyLogTlsClient client = new KeyLogTlsClient(ProtocolVersion.TLSv12, CIPHER_SUITE_12, null);
        connect(client, new KeyLogTlsServer(ProtocolVersion.TLSv12, CIPHER_SUITE_12));

        byte[] masterSecret = assertLoggedByBothPeers(TlsKeyLogLabel.CLIENT_RANDOM, client.getClientRandom());

        assertEquals("master secret length", 48, masterSecret.length);

        for (int i = 0; i < TLS13_LABELS.length; ++i)
        {
            assertEquals(TLS13_LABELS[i] + " logged for TLS 1.2", 0,
                RecordingTlsKeyLog.getEntries(TLS13_LABELS[i]).size());
        }

        assertEquals("unexpected records", 2, RecordingTlsKeyLog.getEntries().size());
    }

    /**
     * An abbreviated handshake derives no new master secret, it reuses the session's, so a report
     * tied to establishing one would miss it entirely. RFC 9850 still needs a record here, because
     * the ClientHello random that identifies the connection is a fresh one and it is what an
     * analyser will look the secret up by.
     */
    public void testTLSv12Resumed() throws Exception
    {
        KeyLogTlsServer server = new KeyLogTlsServer(ProtocolVersion.TLSv12, CIPHER_SUITE_12);

        RecordingTlsKeyLog.reset();

        KeyLogTlsClient first = new KeyLogTlsClient(ProtocolVersion.TLSv12, CIPHER_SUITE_12, null);
        connect(first, server);

        byte[] firstRandom = first.getClientRandom();
        byte[] firstMasterSecret = assertLoggedByBothPeers(TlsKeyLogLabel.CLIENT_RANDOM, firstRandom);

        TlsSession session = first.getResumableSession();
        assertNotNull("no resumable session offered", session);
        server.cacheSession();

        RecordingTlsKeyLog.reset();

        KeyLogTlsClient second = new KeyLogTlsClient(ProtocolVersion.TLSv12, CIPHER_SUITE_12, session);
        connect(second, server);

        assertTrue("the second handshake was not a resumption", second.isResumedSession());

        byte[] secondRandom = second.getClientRandom();
        assertFalse("a resumed handshake still has its own ClientHello random",
            Arrays.areEqual(firstRandom, secondRandom));

        byte[] secondMasterSecret = assertLoggedByBothPeers(TlsKeyLogLabel.CLIENT_RANDOM, secondRandom);

        assertTrue("a resumed session reuses the master secret",
            Arrays.areEqual(firstMasterSecret, secondMasterSecret));
    }

    /**
     * Assert the label was logged exactly twice, once by each peer, against the connection's real
     * ClientHello random and with both peers having derived the same secret. Returns that secret.
     */
    private static byte[] assertLoggedByBothPeers(String label, byte[] clientRandom)
    {
        List entries = RecordingTlsKeyLog.getEntries(label);

        assertEquals(label + " record count", 2, entries.size());

        // Which peer got there first is a race between the two handshake threads, so these are
        // just the two records, not a known client one and a known server one.
        RecordingTlsKeyLog.Entry first = (RecordingTlsKeyLog.Entry)entries.get(0);
        RecordingTlsKeyLog.Entry second = (RecordingTlsKeyLog.Entry)entries.get(1);

        assertTrue(label + " client_random", Arrays.areEqual(clientRandom, first.getClientRandom()));
        assertTrue(label + " client_random", Arrays.areEqual(clientRandom, second.getClientRandom()));

        assertTrue(label + " peers disagree", Arrays.areEqual(first.getSecret(), second.getSecret()));

        return first.getSecret();
    }

    /**
     * Run one handshake to completion over a pipe, echoing a block of data so that both peers get
     * as far as application data before closing.
     */
    private static void connect(KeyLogTlsClient client, KeyLogTlsServer server) throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol, server);
        serverThread.start();

        clientProtocol.connect(client);

        byte[] data = new byte[1000];
        client.getCrypto().getSecureRandom().nextBytes(data);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echo = new byte[data.length];
        int count = Streams.readFully(clientProtocol.getInputStream(), echo);

        assertEquals(data.length, count);
        assertTrue(Arrays.areEqual(data, echo));

        output.close();

        serverThread.join();
    }

    static class KeyLogTlsClient
        extends MockTlsClient
    {
        private final ProtocolVersion version;
        private final int cipherSuite;

        KeyLogTlsClient(ProtocolVersion version, int cipherSuite, TlsSession session)
        {
            super(session);

            this.version = version;
            this.cipherSuite = cipherSuite;
        }

        byte[] getClientRandom()
        {
            return context.getSecurityParametersConnection().getClientRandom();
        }

        boolean isResumedSession()
        {
            return context.getSecurityParametersConnection().isResumedSession();
        }

        TlsSession getResumableSession()
        {
            return context.getResumableSession();
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return version.only();
        }

        protected int[] getSupportedCipherSuites()
        {
            return TlsUtils.getSupportedCipherSuites(getCrypto(), new int[]{ cipherSuite });
        }
    }

    static class KeyLogTlsServer
        extends MockTlsServer
    {
        private final ProtocolVersion version;
        private final int cipherSuite;

        private TlsSession cachedSession;

        KeyLogTlsServer(ProtocolVersion version, int cipherSuite)
        {
            this.version = version;
            this.cipherSuite = cipherSuite;
        }

        /**
         * Take the session just negotiated into this server's (one entry) session cache, so that a
         * later ClientHello naming it can be resumed.
         */
        void cacheSession()
        {
            this.cachedSession = context.getResumableSession();
        }

        /**
         * AbstractTlsServer issues no session ID by default, and a session without one is never
         * resumable, so a server that wants to be resumed has to mint one.
         */
        public byte[] getNewSessionID()
        {
            byte[] sessionID = new byte[32];
            getCrypto().getSecureRandom().nextBytes(sessionID);
            return sessionID;
        }

        public TlsSession getSessionToResume(byte[] sessionID)
        {
            if (null != cachedSession && Arrays.areEqual(sessionID, cachedSession.getSessionID()))
            {
                return cachedSession;
            }

            return null;
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return version.only();
        }

        protected int[] getSupportedCipherSuites()
        {
            return TlsUtils.getSupportedCipherSuites(getCrypto(), new int[]{ cipherSuite });
        }
    }

    static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;
        private final TlsServer server;

        ServerThread(TlsServerProtocol serverProtocol, TlsServer server)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
        }

        public void run()
        {
            try
            {
                serverProtocol.accept(server);
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
                // Deliberately swallowed, as in TlsProtocolTest: the client side reports the failure.
            }
        }
    }
}
