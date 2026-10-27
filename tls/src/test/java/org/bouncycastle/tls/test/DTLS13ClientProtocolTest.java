package org.bouncycastle.tls.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ClientHello;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.KeyShareEntry;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * Isolated coverage of the DTLS 1.3 client's ServerHello handling. There is no DTLS 1.3 server in the tree
 * yet, so these tests script a single ServerHello onto the wire and assert that the client enters the DTLS
 * 1.3 path and fails with a specific alert rather than hanging or silently taking the DTLS 1.2 path. A
 * complete DTLS 1.3 handshake is only exercised once the server half exists.
 */
public class DTLS13ClientProtocolTest
    extends TestCase
{
    private static final int MTU = 1500;

    /**
     * A ServerHello selecting a version later than DTLS 1.3 must be refused outright: this implementation
     * does not know its semantics, and processing it as DTLS 1.3 would be wrong.
     */
    public void testServerSelectsUnsupportedFutureVersion() throws Exception
    {
        // {0xFE, 0xFB} is one version later than DTLS 1.3 and is not implemented here
        short alertDescription = connectAndExpectFatalAlert(new byte[]{ (byte)0xFE, (byte)0xFB });

        assertEquals("alert for an unimplemented future version", AlertDescription.protocol_version,
            alertDescription);
    }

    /**
     * A DTLS 1.3 ServerHello with no "key_share" and no pre-shared key is illegal (RFC 8446 4.1.3/4.2.8).
     * Reaching that check at all proves the client routed the ServerHello into its DTLS 1.3 path: the DTLS
     * 1.2 path has no such requirement and would have gone on to look for a ServerKeyExchange.
     */
    public void testDTLSv13ServerHelloWithoutKeyShare() throws Exception
    {
        short alertDescription = connectAndExpectFatalAlert(new byte[]{ (byte)0xFE, (byte)0xFC });

        assertEquals("alert for a DTLS 1.3 ServerHello with no key_share", AlertDescription.illegal_parameter,
            alertDescription);
    }

    /**
     * RFC 9147 5.1. DTLS 1.3 has no HelloVerifyRequest, so a server that sent one must not then select DTLS
     * 1.3: the handshake would have been reached through a denial-of-service countermeasure DTLS 1.3 does not
     * have, and without this check the DTLS 1.2 cookie exchange is a way in to a 1.3 handshake. A
     * version-straddling client - one that offers DTLS 1.2 as well - has to accept the HelloVerifyRequest,
     * because the peer may genuinely be a DTLS 1.2 server, so the refusal can only come afterwards.
     * <p>
     * The server half of this sequence is scripted rather than driven by DTLSServerProtocol, because a
     * conforming BC server no longer produces it: DTLSServerProtocol.generateServerHello refuses to select
     * DTLS 1.3 behind a HelloVerifyRequest front end at all (see
     * DTLS13ProtocolTest.testServerRefusesToSelectDTLSv13BehindAHelloVerifyRequest). Only a synthetic peer
     * can still exercise the client's side of the rule.
     * </p>
     */
    public void testClientRefusesDTLSv13SelectedAfterAHelloVerifyRequest() throws Exception
    {
        byte[] cookie = new byte[]{ (byte)0xA1, (byte)0xB2, (byte)0xC3, (byte)0xD4 };

        byte[][] script = new byte[][]{
            // RFC 6347 4.2.1. HelloVerifyRequest, message_seq 0, answering the first ClientHello
            createHelloVerifyRequestRecord(cookie, 0),
            // and then DTLS 1.3 anyway, at the message_seq the client expects a ServerHello at after one
            createServerHelloRecord(new byte[]{ (byte)0xFE, (byte)0xFC }, 1, 1)
        };

        ScriptedServerHelloTransport transport = new ScriptedServerHelloTransport(script);

        TlsFatalAlert fatalAlert = connectAndExpectFatalAlert(transport,
            ProtocolVersion.DTLSv13.downTo(ProtocolVersion.DTLSv12));

        assertEquals("alert for DTLS 1.3 selected after a HelloVerifyRequest",
            AlertDescription.illegal_parameter, fatalAlert.getAlertDescription());

        /*
         * The alert description alone would not say which check raised it - the DTLS 1.3 ServerHello scripted
         * here carries no "key_share" either, and that check raises the same alert a few lines later. The
         * message, and the fact that the client answered the HelloVerifyRequest with a second ClientHello,
         * pin it to the rule under test.
         */
        assertEquals("the HelloVerifyRequest check must be the one that raised it",
            "illegal_parameter(47); Server selected DTLS 1.3 after sending a HelloVerifyRequest",
            fatalAlert.getMessage());

        assertEquals("the client must have answered the HelloVerifyRequest", 2,
            transport.clientHellosSeen());

        /*
         * A retransmission of the first ClientHello would also be a second datagram carrying a ClientHello,
         * so check the message_seq advanced: RFC 6347 4.2.2 requires the ClientHello answering a
         * HelloVerifyRequest to be a new message, at message_seq 1.
         */
        assertEquals("the first ClientHello is at message_seq 0", 0, transport.clientHelloSeq(0));
        assertEquals("the second ClientHello must be a new message, not a retransmission", 1,
            transport.clientHelloSeq(1));
    }

    /**
     * RFC 9147 5.1: a DTLS 1.3 server's cookie exchange is a HelloRetryRequest carrying a cookie and, when the
     * client's key share is already acceptable, nothing else (RFC 9846 4.2.4 asks for the minimal set of
     * extensions). The client must answer with a second ClientHello that echoes the cookie and keeps its
     * original "key_share" (RFC 9846 4.2.2: the shares are replaced only if the HelloRetryRequest supplied
     * a "key_share"). OpenSSL 4.1's s_server sends exactly this on every DTLS 1.3 connection, and the client
     * used to refuse it with missing_extension(key_share). The server here is scripted: BC's own server never
     * sends a cookie without a group change. It answers the second ClientHello with a second
     * HelloRetryRequest, which the client must refuse with unexpected_message (RFC 9846 4.2.4) - reaching
     * that proves the first one was accepted and answered.
     */
    public void testClientAcceptsACookieOnlyHelloRetryRequest() throws Exception
    {
        byte[] cookie = new byte[64];
        for (int i = 0; i < cookie.length; ++i)
        {
            cookie[i] = (byte)(0xC0 + i);
        }

        byte[][] script = new byte[][]{
            createHelloRetryRequestRecord(cookie, 0, 0),
            createHelloRetryRequestRecord(cookie, 1, 1)
        };

        ScriptedServerHelloTransport transport = new ScriptedServerHelloTransport(script);

        TlsFatalAlert fatalAlert = connectAndExpectFatalAlert(transport, ProtocolVersion.DTLSv13.only());

        assertEquals("the second HelloRetryRequest must be refused, not the first",
            AlertDescription.unexpected_message, fatalAlert.getAlertDescription());

        assertEquals("the client must have answered the HelloRetryRequest", 2, transport.clientHellosSeen());
        assertEquals("the second ClientHello must be a new message", 1, transport.clientHelloSeq(1));

        ClientHello first = parseClientHello(transport.clientHello(0));
        ClientHello second = parseClientHello(transport.clientHello(1));

        assertNull("the first ClientHello carries no cookie",
            TlsExtensionsUtils.getCookieExtension(first.getExtensions()));
        assertTrue("the second ClientHello must echo the HelloRetryRequest cookie",
            Arrays.areEqual(cookie, TlsExtensionsUtils.getCookieExtension(second.getExtensions())));

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
        ScriptedServerHelloTransport transport = new ScriptedServerHelloTransport(
            new byte[][]{ createHelloRetryRequestRecord(null, 0, 0) });

        TlsFatalAlert fatalAlert = connectAndExpectFatalAlert(transport, ProtocolVersion.DTLSv13.only());

        assertEquals(AlertDescription.illegal_parameter, fatalAlert.getAlertDescription());
        assertEquals(1, transport.clientHellosSeen());
    }

    private short connectAndExpectFatalAlert(byte[] selectedVersion) throws Exception
    {
        ScriptedServerHelloTransport transport = new ScriptedServerHelloTransport(
            new byte[][]{ createServerHelloRecord(selectedVersion, 0, 0) });

        return connectAndExpectFatalAlert(transport, ProtocolVersion.DTLSv13.only()).getAlertDescription();
    }

    private TlsFatalAlert connectAndExpectFatalAlert(ScriptedServerHelloTransport transport,
        final ProtocolVersion[] clientVersions) throws Exception
    {
        MockDTLSClient client = new MockDTLSClient(null)
        {
            public int[] getCipherSuites()
            {
                return new int[]{ CipherSuite.TLS_AES_128_GCM_SHA256 };
            }

            protected ProtocolVersion[] getSupportedVersions()
            {
                return clientVersions;
            }
        };

        // NOTE: Bounded so that a client which does not fail as expected ends the test instead of hanging
        client.setHandshakeTimeoutMillis(5000);

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();

        try
        {
            clientProtocol.connect(client, transport);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            assertTrue("server never received a ClientHello", transport.sawClientHello());

            return fatalAlert;
        }

        fail("expected the client to raise a fatal alert");
        return null;
    }

    /**
     * RFC 6347 4.2.1. A DTLS plaintext record carrying a HelloVerifyRequest, whose 'server_version' is DTLS
     * 1.0 as that section requires regardless of the version being negotiated.
     */
    private static byte[] createHelloVerifyRequestRecord(byte[] cookie, long recordSeq) throws IOException
    {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        // server_version: DTLS 1.0
        body.write(0xFE);
        body.write(0xFF);
        body.write(cookie.length);
        body.write(cookie, 0, cookie.length);

        return createPlaintextRecord(HandshakeType.hello_verify_request, 0, recordSeq, body.toByteArray());
    }

    /** RFC 9846 4.2.4: the 'random' value that marks a ServerHello as a HelloRetryRequest. */
    private static final byte[] HELLO_RETRY_REQUEST_RANDOM = new byte[]{
        (byte)0xCF, (byte)0x21, (byte)0xAD, (byte)0x74, (byte)0xE5, (byte)0x9A, (byte)0x61, (byte)0x11,
        (byte)0xBE, (byte)0x1D, (byte)0x8C, (byte)0x02, (byte)0x1E, (byte)0x65, (byte)0xB8, (byte)0x91,
        (byte)0xC2, (byte)0xA2, (byte)0x11, (byte)0x16, (byte)0x7A, (byte)0xBB, (byte)0x8C, (byte)0x5E,
        (byte)0x07, (byte)0x9E, (byte)0x09, (byte)0xE2, (byte)0xC8, (byte)0xA8, (byte)0x33, (byte)0x9C };

    /**
     * A DTLS plaintext record carrying a DTLS 1.3 HelloRetryRequest (RFC 9846 4.2.4: a ServerHello with the
     * special 'random') whose only extensions are "supported_versions" and, unless null, a "cookie" - the
     * shape of the RFC 9147 5.1 cookie exchange.
     */
    private static byte[] createHelloRetryRequestRecord(byte[] cookie, int messageSeq, long recordSeq)
        throws IOException
    {
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        writeUint16(extensions, ExtensionType.supported_versions);
        writeUint16(extensions, 2);
        extensions.write(0xFE);
        extensions.write(0xFC);
        if (null != cookie)
        {
            writeUint16(extensions, ExtensionType.cookie);
            writeUint16(extensions, 2 + cookie.length);
            writeUint16(extensions, cookie.length);
            extensions.write(cookie, 0, cookie.length);
        }

        byte[] extensionsData = extensions.toByteArray();

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        // legacy_version
        body.write(0xFE);
        body.write(0xFD);
        body.write(HELLO_RETRY_REQUEST_RANDOM, 0, HELLO_RETRY_REQUEST_RANDOM.length);
        // legacy_session_id_echo: the client offered none
        body.write(0);
        writeUint16(body, CipherSuite.TLS_AES_128_GCM_SHA256);
        // legacy_compression_method
        body.write(0);
        writeUint16(body, extensionsData.length);
        body.write(extensionsData, 0, extensionsData.length);

        return createPlaintextRecord(HandshakeType.server_hello, messageSeq, recordSeq, body.toByteArray());
    }

    /** Parses the ClientHello out of a single-record epoch-0 datagram the scripted transport captured. */
    private static ClientHello parseClientHello(byte[] datagram) throws IOException
    {
        int fragmentLength = ((datagram[22] & 0xFF) << 16) | ((datagram[23] & 0xFF) << 8) | (datagram[24] & 0xFF);

        return ClientHello.parse(new ByteArrayInputStream(datagram, 25, fragmentLength), new ByteArrayOutputStream());
    }

    /**
     * A DTLS plaintext record (RFC 9147 4) carrying a single unfragmented ServerHello, selecting the given
     * version through the "supported_versions" extension.
     */
    private static byte[] createServerHelloRecord(byte[] selectedVersion, int messageSeq, long recordSeq)
        throws IOException
    {
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        writeUint16(extensions, ExtensionType.supported_versions);
        writeUint16(extensions, selectedVersion.length);
        extensions.write(selectedVersion, 0, selectedVersion.length);

        byte[] extensionsData = extensions.toByteArray();

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        // legacy_version
        body.write(0xFE);
        body.write(0xFD);
        // random: fixed, and deliberately not the HelloRetryRequest value of RFC 8446 4.1.3
        for (int i = 0; i < 32; ++i)
        {
            body.write(i);
        }
        // legacy_session_id_echo: the client offered none
        body.write(0);
        writeUint16(body, CipherSuite.TLS_AES_128_GCM_SHA256);
        // legacy_compression_method
        body.write(0);
        writeUint16(body, extensionsData.length);
        body.write(extensionsData, 0, extensionsData.length);

        return createPlaintextRecord(HandshakeType.server_hello, messageSeq, recordSeq, body.toByteArray());
    }

    /**
     * RFC 9147 4. One epoch-0 plaintext record carrying one unfragmented handshake message. The
     * 'sequence_number' is the caller's, because the record layer's replay window discards a repeat of one it
     * has already accepted, so each record of a scripted sequence needs its own.
     */
    private static byte[] createPlaintextRecord(short msgType, int messageSeq, long recordSeq, byte[] bodyData)
        throws IOException
    {
        ByteArrayOutputStream record = new ByteArrayOutputStream();
        record.write(ContentType.handshake);
        // legacy_record_version
        record.write(0xFE);
        record.write(0xFD);
        // epoch
        writeUint16(record, 0);
        // sequence_number (48 bits)
        for (int i = 5; i >= 0; --i)
        {
            record.write((int)((recordSeq >>> (8 * i)) & 0xFF));
        }
        writeUint16(record, 12 + bodyData.length);

        record.write(msgType);
        writeUint24(record, bodyData.length);
        writeUint16(record, messageSeq);
        // fragment_offset
        writeUint24(record, 0);
        // fragment_length
        writeUint24(record, bodyData.length);
        record.write(bodyData, 0, bodyData.length);

        return record.toByteArray();
    }

    private static void writeUint16(ByteArrayOutputStream buf, int i)
    {
        buf.write((i >>> 8) & 0xFF);
        buf.write(i & 0xFF);
    }

    private static void writeUint24(ByteArrayOutputStream buf, int i)
    {
        buf.write((i >>> 16) & 0xFF);
        buf.write((i >>> 8) & 0xFF);
        buf.write(i & 0xFF);
    }

    /**
     * Answers each ClientHello with the next prepared record, and nothing once the script runs out. One
     * record per ClientHello is enough for both shapes used here: a single ServerHello, and a
     * HelloVerifyRequest followed by the ServerHello that answers the second ClientHello.
     */
    private static class ScriptedServerHelloTransport
        implements DatagramTransport
    {
        private final byte[][] script;

        private final int[] clientHelloSeqs = new int[8];
        private final byte[][] clientHellos = new byte[8][];

        private int clientHellosSeen = 0;
        private byte[] pending = null;

        ScriptedServerHelloTransport(byte[][] script)
        {
            this.script = script;
        }

        boolean sawClientHello()
        {
            return clientHellosSeen > 0;
        }

        int clientHellosSeen()
        {
            return clientHellosSeen;
        }

        /** The datagram carrying the ClientHello at the given index. */
        byte[] clientHello(int index)
        {
            return clientHellos[index];
        }

        /**
         * The DTLS handshake message_seq of the ClientHello at the given index, so that a retransmission of
         * an earlier ClientHello can be told apart from a genuinely new one - both are datagrams carrying a
         * ClientHello, and only the message_seq distinguishes them.
         */
        int clientHelloSeq(int index)
        {
            return clientHelloSeqs[index];
        }

        public int getReceiveLimit()
        {
            return MTU;
        }

        public int getSendLimit()
        {
            return MTU;
        }

        public void send(byte[] buf, int off, int len) throws IOException
        {
            // DTLS plaintext record header (13 bytes), then the DTLS handshake message header
            if (clientHellosSeen < script.length && len > 13 && (buf[off] & 0xFF) == ContentType.handshake
                && (buf[off + 13] & 0xFF) == HandshakeType.client_hello)
            {
                // Handshake message header: msg_type, length, then message_seq at offsets 4 and 5
                if (clientHellosSeen < clientHelloSeqs.length)
                {
                    clientHelloSeqs[clientHellosSeen] = ((buf[off + 17] & 0xFF) << 8)
                        | (buf[off + 18] & 0xFF);
                    clientHellos[clientHellosSeen] = Arrays.copyOfRange(buf, off, off + len);
                }

                this.pending = script[clientHellosSeen++];
            }
        }

        public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException
        {
            if (null == pending)
            {
                return -1;
            }

            byte[] record = pending;
            this.pending = null;

            if (record.length > len)
            {
                return -1;
            }

            System.arraycopy(record, 0, buf, off, record.length);
            return record.length;
        }

        public void close() throws IOException
        {
        }
    }
}
