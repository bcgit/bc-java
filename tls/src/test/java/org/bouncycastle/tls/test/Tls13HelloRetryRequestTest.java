package org.bouncycastle.tls.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ClientHello;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.KeyShareEntry;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * The TLS 1.3 client's handling of a HelloRetryRequest that carries a cookie but no "key_share": the shape a
 * stateless server sends (RFC 9846 4.3.2, and OpenSSL's s_server -stateless) when the client's share is
 * already acceptable. RFC 9846 4.2.4 asks for the minimal set of extensions, and 4.2.2 replaces the shares
 * only "If a "key_share" extension was supplied in the HelloRetryRequest", so the second ClientHello must
 * echo the cookie and keep its original shares. The server is scripted on the client's own streams; it
 * answers the second ClientHello with a second HelloRetryRequest, which the client must refuse with
 * unexpected_message (RFC 9846 4.2.4) - reaching that proves the first one was accepted and answered.
 */
public class Tls13HelloRetryRequestTest
    extends TestCase
{
    /** RFC 9846 4.2.4: the 'random' value that marks a ServerHello as a HelloRetryRequest. */
    private static final byte[] HELLO_RETRY_REQUEST_RANDOM = new byte[]{
        (byte)0xCF, (byte)0x21, (byte)0xAD, (byte)0x74, (byte)0xE5, (byte)0x9A, (byte)0x61, (byte)0x11,
        (byte)0xBE, (byte)0x1D, (byte)0x8C, (byte)0x02, (byte)0x1E, (byte)0x65, (byte)0xB8, (byte)0x91,
        (byte)0xC2, (byte)0xA2, (byte)0x11, (byte)0x16, (byte)0x7A, (byte)0xBB, (byte)0x8C, (byte)0x5E,
        (byte)0x07, (byte)0x9E, (byte)0x09, (byte)0xE2, (byte)0xC8, (byte)0xA8, (byte)0x33, (byte)0x9C };

    public void testClientAcceptsACookieOnlyHelloRetryRequest() throws Exception
    {
        byte[] cookie = new byte[64];
        for (int i = 0; i < cookie.length; ++i)
        {
            cookie[i] = (byte)(0xC0 + i);
        }

        ScriptedServer server = new ScriptedServer(cookie, 2);

        TlsFatalAlert fatalAlert = connectAndExpectFatalAlert(server);

        assertEquals("the second HelloRetryRequest must be refused, not the first",
            AlertDescription.unexpected_message, fatalAlert.getAlertDescription());

        Vector clientHellos = server.clientHellos();
        assertEquals("the client must have answered the HelloRetryRequest", 2, clientHellos.size());

        ClientHello first = (ClientHello)clientHellos.elementAt(0);
        ClientHello second = (ClientHello)clientHellos.elementAt(1);

        assertNull("the first ClientHello carries no cookie",
            TlsExtensionsUtils.getCookieExtension(first.getExtensions()));
        assertTrue("the second ClientHello must echo the HelloRetryRequest cookie",
            Arrays.areEqual(cookie, TlsExtensionsUtils.getCookieExtension(second.getExtensions())));
        assertTrue("legacy_session_id must be unchanged",
            Arrays.areEqual(first.getSessionID(), second.getSessionID()));

        Vector firstShares = TlsExtensionsUtils.getKeyShareClientHello(first.getExtensions());
        Vector secondShares = TlsExtensionsUtils.getKeyShareClientHello(second.getExtensions());
        assertNotNull(firstShares);
        assertNotNull("the second ClientHello must keep a key_share", secondShares);
        assertEquals("the original shares must be kept as they were", firstShares.size(), secondShares.size());
        for (int i = 0; i < firstShares.size(); ++i)
        {
            KeyShareEntry a = (KeyShareEntry)firstShares.elementAt(i);
            KeyShareEntry b = (KeyShareEntry)secondShares.elementAt(i);
            assertEquals("key_share group", a.getNamedGroup(), b.getNamedGroup());
            assertTrue("key_share key_exchange", Arrays.areEqual(a.getKeyExchange(), b.getKeyExchange()));
        }
    }

    /**
     * RFC 9846 4.2.4: "Clients MUST abort the handshake with an "illegal_parameter" alert if the
     * HelloRetryRequest would not result in any change in the ClientHello." No key_share and no cookie is that
     * case.
     */
    public void testClientRefusesAHelloRetryRequestThatChangesNothing() throws Exception
    {
        ScriptedServer server = new ScriptedServer(null, 1);

        TlsFatalAlert fatalAlert = connectAndExpectFatalAlert(server);

        assertEquals(AlertDescription.illegal_parameter, fatalAlert.getAlertDescription());
        assertEquals(1, server.clientHellos().size());
    }

    private static TlsFatalAlert connectAndExpectFatalAlert(ScriptedServer server) throws Exception
    {
        MockTlsClient client = new MockTlsClient(null);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(server, server.clientOutput());

        try
        {
            clientProtocol.connect(client);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            assertTrue("server never received a ClientHello", server.clientHellos().size() > 0);

            return fatalAlert;
        }

        fail("expected the client to raise a fatal alert");
        return null;
    }

    /**
     * The client's input stream. Each time the client reads with nothing pending, the ClientHello it has
     * written since the last time is parsed and answered with a HelloRetryRequest carrying the cookie (if
     * any) and no "key_share", up to the given number of them; then end of stream.
     */
    private static class ScriptedServer
        extends InputStream
    {
        private final byte[] cookie;
        private final int helloRetryRequests;
        private final ByteArrayOutputStream clientOutput = new ByteArrayOutputStream();
        private final Vector clientHellos = new Vector();

        private int consumed = 0;
        private int sent = 0;
        private byte[] pending = null;
        private int pendingPos = 0;

        ScriptedServer(byte[] cookie, int helloRetryRequests)
        {
            this.cookie = cookie;
            this.helloRetryRequests = helloRetryRequests;
        }

        ByteArrayOutputStream clientOutput()
        {
            return clientOutput;
        }

        Vector clientHellos()
        {
            return clientHellos;
        }

        public int read() throws IOException
        {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xFF);
        }

        public int read(byte[] buf, int off, int len) throws IOException
        {
            if (null == pending || pendingPos >= pending.length)
            {
                ClientHello clientHello = takeClientHello();
                if (null == clientHello || sent >= helloRetryRequests)
                {
                    return -1;
                }

                this.pending = createHelloRetryRequestRecord(clientHello, cookie);
                this.pendingPos = 0;
                ++sent;
            }

            int n = Math.min(len, pending.length - pendingPos);
            System.arraycopy(pending, pendingPos, buf, off, n);
            pendingPos += n;
            return n;
        }

        /**
         * The next ClientHello among the records the client has written since the last call, skipping
         * anything else (the compatibility-mode change_cipher_spec, say). Each handshake message is assumed
         * to sit whole in one record, which holds for a ClientHello of this size.
         */
        private ClientHello takeClientHello() throws IOException
        {
            byte[] written = clientOutput.toByteArray();
            while (consumed + 5 <= written.length)
            {
                int contentType = written[consumed] & 0xFF;
                int recordLength = ((written[consumed + 3] & 0xFF) << 8) | (written[consumed + 4] & 0xFF);
                int bodyOff = consumed + 5;
                if (bodyOff + recordLength > written.length)
                {
                    break;
                }
                consumed = bodyOff + recordLength;

                if (ContentType.handshake == contentType && recordLength >= 4
                    && (written[bodyOff] & 0xFF) == HandshakeType.client_hello)
                {
                    int messageLength = ((written[bodyOff + 1] & 0xFF) << 16) | ((written[bodyOff + 2] & 0xFF) << 8)
                        | (written[bodyOff + 3] & 0xFF);

                    ClientHello clientHello = ClientHello.parse(
                        new ByteArrayInputStream(written, bodyOff + 4, messageLength), null);
                    clientHellos.addElement(clientHello);
                    return clientHello;
                }
            }
            return null;
        }
    }

    /**
     * A TLS record carrying a HelloRetryRequest (RFC 9846 4.2.4: a ServerHello with the special 'random')
     * that echoes the ClientHello's legacy_session_id, selects TLS_AES_128_GCM_SHA256, and carries only
     * "supported_versions" and, unless null, a "cookie".
     */
    private static byte[] createHelloRetryRequestRecord(ClientHello clientHello, byte[] cookie) throws IOException
    {
        assertTrue("the client must offer the suite this server selects",
            Arrays.contains(clientHello.getCipherSuites(), CipherSuite.TLS_AES_128_GCM_SHA256));

        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        writeUint16(extensions, ExtensionType.supported_versions);
        writeUint16(extensions, 2);
        extensions.write(0x03);
        extensions.write(0x04);
        if (null != cookie)
        {
            writeUint16(extensions, ExtensionType.cookie);
            writeUint16(extensions, 2 + cookie.length);
            writeUint16(extensions, cookie.length);
            extensions.write(cookie, 0, cookie.length);
        }

        byte[] extensionsData = extensions.toByteArray();
        byte[] sessionID = clientHello.getSessionID();

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        // legacy_version
        body.write(0x03);
        body.write(0x03);
        body.write(HELLO_RETRY_REQUEST_RANDOM, 0, HELLO_RETRY_REQUEST_RANDOM.length);
        body.write(sessionID.length);
        body.write(sessionID, 0, sessionID.length);
        writeUint16(body, CipherSuite.TLS_AES_128_GCM_SHA256);
        // legacy_compression_method
        body.write(0);
        writeUint16(body, extensionsData.length);
        body.write(extensionsData, 0, extensionsData.length);

        byte[] bodyData = body.toByteArray();

        ByteArrayOutputStream record = new ByteArrayOutputStream();
        record.write(ContentType.handshake);
        // legacy_record_version
        record.write(0x03);
        record.write(0x03);
        writeUint16(record, 4 + bodyData.length);
        record.write(HandshakeType.server_hello);
        record.write((bodyData.length >>> 16) & 0xFF);
        record.write((bodyData.length >>> 8) & 0xFF);
        record.write(bodyData.length & 0xFF);
        record.write(bodyData, 0, bodyData.length);

        return record.toByteArray();
    }

    private static void writeUint16(ByteArrayOutputStream buf, int i)
    {
        buf.write((i >>> 8) & 0xFF);
        buf.write(i & 0xFF);
    }
}
