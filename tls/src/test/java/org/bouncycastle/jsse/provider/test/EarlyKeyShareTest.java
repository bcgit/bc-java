package org.bouncycastle.jsse.provider.test;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.Hashtable;
import java.util.Vector;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;

import junit.framework.TestCase;
import org.bouncycastle.jsse.BCSSLEngine;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.tls.ClientHello;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.KeyShareEntry;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ServerHello;
import org.bouncycastle.tls.TlsExtensionsUtils;

/**
 * What a BCJSSE client offers when nothing has been configured: X25519MLKEM768 leads the named
 * groups, and the first ClientHello carries a key share for it as well as for x25519, so a server
 * that supports the hybrid negotiates it without a HelloRetryRequest and one that does not falls
 * back to x25519 at no extra cost (NIST IR 8547 sec. 4.2 names the TLS 1.3 hybrids as the
 * near-term migration path).
 * <p>
 * The handshake tests drive a client and a server SSLEngine against each other in memory and parse
 * the server's first message, which says both whether it was a HelloRetryRequest and which group
 * the server chose.
 */
public class EarlyKeyShareTest
    extends TestCase
{
    public void testDefaultClientHelloOffersHybridFirstWithAKeyShare() throws Exception
    {
        ProviderUtils.setupHighPriority(false);

        Hashtable extensions = defaultClientHelloExtensions();

        int[] supportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(extensions);
        assertNotNull("no supported_groups extension", supportedGroups);
        assertEquals("most preferred group", NamedGroup.getText(NamedGroup.X25519MLKEM768),
            NamedGroup.getText(supportedGroups[0]));
        assertEquals("second group", NamedGroup.getText(NamedGroup.x25519), NamedGroup.getText(supportedGroups[1]));

        assertKeyShares(new int[]{ NamedGroup.X25519MLKEM768, NamedGroup.x25519 }, extensions);
    }

    /**
     * x25519 is not a FIPS group, so in approved mode the classical share falls back to secp256r1,
     * the first classical group that is.
     */
    public void testDefaultClientHelloApprovedMode() throws Exception
    {
        FipsTestUtils.setupFipsSuite();
        try
        {
            Hashtable extensions = defaultClientHelloExtensions();

            int[] supportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(extensions);
            assertNotNull("no supported_groups extension", supportedGroups);
            assertEquals("most preferred group", NamedGroup.getText(NamedGroup.X25519MLKEM768),
                NamedGroup.getText(supportedGroups[0]));

            assertKeyShares(new int[]{ NamedGroup.X25519MLKEM768, NamedGroup.secp256r1 }, extensions);
        }
        finally
        {
            FipsTestUtils.teardownFipsSuite();
        }
    }

    private static void assertKeyShares(int[] expected, Hashtable extensions) throws Exception
    {
        Vector shares = TlsExtensionsUtils.getKeyShareClientHello(extensions);
        assertNotNull("no key_share extension", shares);
        assertEquals("key_share count", expected.length, shares.size());
        for (int i = 0; i < expected.length; ++i)
        {
            assertEquals("key_share " + i, NamedGroup.getText(expected[i]),
                NamedGroup.getText(((KeyShareEntry)shares.elementAt(i)).getNamedGroup()));
        }
    }

    /**
     * The extensions of the first ClientHello of a TLS 1.3 client left at its defaults, taken from
     * the provider the caller has set up.
     */
    private static Hashtable defaultClientHelloExtensions() throws Exception
    {
        SSLContext clientContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
        clientContext.init(null, null, null);

        SSLEngine clientEngine = clientContext.createSSLEngine();
        clientEngine.setUseClientMode(true);
        clientEngine.setEnabledProtocols(new String[]{ "TLSv1.3" });
        clientEngine.beginHandshake();

        ByteBuffer clientToServer = ByteBuffer.allocate(clientEngine.getSession().getPacketBufferSize());
        clientEngine.wrap(ByteBuffer.allocate(0), clientToServer);
        clientToServer.flip();

        byte[] record = new byte[clientToServer.remaining()];
        clientToServer.get(record);

        assertEquals("handshake record", ContentType.handshake, record[0] & 0xFF);
        assertEquals("ClientHello", HandshakeType.client_hello, record[5] & 0xFF);

        int messageLength = ((record[6] & 0xFF) << 16) | ((record[7] & 0xFF) << 8) | (record[8] & 0xFF);

        return ClientHello.parse(new ByteArrayInputStream(record, 9, messageLength), null).getExtensions();
    }

    public void testDefaultClientAndServerNegotiateHybridWithoutRetry() throws Exception
    {
        ServerHello serverHello = handshakeAgainstServer(null);

        assertFalse("HelloRetryRequest sent", serverHello.isHelloRetryRequest());
        assertServerKeyShare(NamedGroup.X25519MLKEM768, serverHello);
    }

    public void testClassicalServerGetsX25519WithoutRetry() throws Exception
    {
        ServerHello serverHello = handshakeAgainstServer(new String[]{ "x25519", "secp256r1", "secp384r1" });

        assertFalse("HelloRetryRequest sent", serverHello.isHelloRetryRequest());
        assertServerKeyShare(NamedGroup.x25519, serverHello);
    }

    /**
     * A server with no group the default client sends a share for has to retry; this is what shows
     * the two tests above would see a HelloRetryRequest if one were sent.
     */
    public void testServerWithoutAnEarlyShareGroupRetries() throws Exception
    {
        ServerHello serverHello = handshakeAgainstServer(new String[]{ "secp256r1" });

        assertTrue("no HelloRetryRequest", serverHello.isHelloRetryRequest());
        assertEquals("retry group", NamedGroup.getText(NamedGroup.secp256r1),
            NamedGroup.getText(TlsExtensionsUtils.getKeyShareHelloRetryRequest(serverHello.getExtensions())));
    }

    private static void assertServerKeyShare(int expected, ServerHello serverHello) throws Exception
    {
        KeyShareEntry serverShare = TlsExtensionsUtils.getKeyShareServerHello(serverHello.getExtensions());
        assertNotNull("no key_share extension", serverShare);
        assertEquals("negotiated group", NamedGroup.getText(expected), NamedGroup.getText(serverShare.getNamedGroup()));
    }

    /**
     * Completes a TLS 1.3 handshake between a default-configured BCJSSE client and a BCJSSE server,
     * restricted to serverNamedGroups where that is not null, and returns the server's first
     * handshake message.
     */
    private static ServerHello handshakeAgainstServer(String[] serverNamedGroups) throws Exception
    {
        ProviderUtils.setupHighPriority(false);

        KeyStore[] credential = NamedGroupTestUtil.createRSACredential();
        SSLContext serverContext = NamedGroupTestUtil.createServerContext(ProviderUtils.getProviderBCJSSE(),
            credential[0]);
        SSLContext clientContext = NamedGroupTestUtil.createClientContext(ProviderUtils.getProviderBCJSSE(),
            credential[1]);

        SSLEngine clientEngine = clientContext.createSSLEngine("localhost", 443);
        clientEngine.setUseClientMode(true);
        clientEngine.setEnabledProtocols(new String[]{ "TLSv1.3" });

        SSLEngine serverEngine = serverContext.createSSLEngine();
        serverEngine.setUseClientMode(false);
        serverEngine.setEnabledProtocols(new String[]{ "TLSv1.3" });
        if (serverNamedGroups != null)
        {
            BCSSLEngine bcServerEngine = (BCSSLEngine)serverEngine;
            BCSSLParameters bcParams = bcServerEngine.getParameters();
            bcParams.setNamedGroups(serverNamedGroups);
            bcServerEngine.setParameters(bcParams);
        }

        ByteBuffer clientToServer = ByteBuffer.allocate(1 << 16);
        ByteBuffer serverToClient = ByteBuffer.allocate(1 << 16);
        ByteBuffer appData = ByteBuffer.allocate(1 << 16);

        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        byte[] serverFirstRecord = null;
        for (int round = 0; round < 20; ++round)
        {
            wrapAll(clientEngine, clientToServer);
            unwrapAll(serverEngine, clientToServer, appData);

            int before = serverToClient.position();
            wrapAll(serverEngine, serverToClient);
            if (serverFirstRecord == null && serverToClient.position() > before)
            {
                serverFirstRecord = new byte[serverToClient.position() - before];
                System.arraycopy(serverToClient.array(), before, serverFirstRecord, 0, serverFirstRecord.length);
            }
            unwrapAll(clientEngine, serverToClient, appData);

            if (isHandshakeDone(clientEngine) && isHandshakeDone(serverEngine))
            {
                break;
            }
        }

        assertTrue("client handshake incomplete", isHandshakeDone(clientEngine));
        assertTrue("server handshake incomplete", isHandshakeDone(serverEngine));
        assertEquals("TLSv1.3", clientEngine.getSession().getProtocol());

        assertNotNull("server sent nothing", serverFirstRecord);
        assertEquals("handshake record", ContentType.handshake, serverFirstRecord[0] & 0xFF);
        assertEquals("ServerHello", HandshakeType.server_hello, serverFirstRecord[5] & 0xFF);

        int messageLength = ((serverFirstRecord[6] & 0xFF) << 16) | ((serverFirstRecord[7] & 0xFF) << 8)
            | (serverFirstRecord[8] & 0xFF);

        return ServerHello.parse(new ByteArrayInputStream(serverFirstRecord, 9, messageLength));
    }

    private static boolean isHandshakeDone(SSLEngine engine)
    {
        return engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    private static void runTasks(SSLEngine engine)
    {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null)
        {
            task.run();
        }
    }

    private static void wrapAll(SSLEngine engine, ByteBuffer out) throws Exception
    {
        ByteBuffer empty = ByteBuffer.allocate(0);
        for (;;)
        {
            runTasks(engine);
            if (engine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_WRAP)
            {
                return;
            }
            SSLEngineResult result = engine.wrap(empty, out);
            assertEquals("wrap", SSLEngineResult.Status.OK, result.getStatus());
            if (result.bytesProduced() == 0)
            {
                return;
            }
        }
    }

    /**
     * Feeds the engine everything buffered in {@code in}, leaving it compacted for the next write.
     */
    private static void unwrapAll(SSLEngine engine, ByteBuffer in, ByteBuffer appData) throws Exception
    {
        in.flip();
        try
        {
            while (in.hasRemaining())
            {
                SSLEngineResult result = engine.unwrap(in, appData);
                runTasks(engine);
                if (result.getStatus() != SSLEngineResult.Status.OK || result.bytesConsumed() == 0)
                {
                    break;
                }
            }
        }
        finally
        {
            in.compact();
        }
    }
}
