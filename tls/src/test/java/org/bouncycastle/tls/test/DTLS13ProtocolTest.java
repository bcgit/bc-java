package org.bouncycastle.tls.test;

import java.io.IOException;
import java.util.Random;
import java.util.Vector;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsFatalAlertReceived;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * End-to-end DTLS 1.3 handshakes between the BC client and the BC server.
 * <p>
 * The assertions are deliberately made against the bytes on the wire, rather than against internal
 * record-layer state, so that a DTLS 1.2 handshake which merely happened to complete could not pass: RFC
 * 9147 4's unified header and RFC 9147 6.1's epoch numbering are both observable from outside.
 */
public class DTLS13ProtocolTest
    extends TestCase
{
    private static final int HANDSHAKE_TIMEOUT_MILLIS = 60000;

    /*
     * RFC 9147 4. Re-derived here rather than read from the package-private DTLS13UnifiedHeader, so that the
     * test checks the encoding independently of the constants the implementation uses.
     */
    private static final int UNIFIED_FIXED_BITS = 0x20;
    private static final int UNIFIED_FIXED_BITS_MASK = 0xE0;
    private static final int UNIFIED_FLAG_CID = 0x10;
    private static final int UNIFIED_FLAG_SEQ16 = 0x08;
    private static final int UNIFIED_FLAG_LENGTH = 0x04;
    private static final int UNIFIED_EPOCH_BITS_MASK = 0x03;

    /** RFC 9147 5.2. The DTLS handshake message header, which the wire keeps and the transcript omits. */
    private static final int MESSAGE_HEADER_LENGTH = 12;

    private static final int PLAINTEXT_HEADER_LENGTH = 13;

    /**
     * RFC 8446 4.1.3. The 'random' of a HelloRetryRequest, which is what distinguishes one from a ServerHello.
     * Spelled out here rather than read from the implementation, so that a test asserting "this is a
     * HelloRetryRequest" does so against the value on the wire.
     */
    private static final byte[] HELLO_RETRY_REQUEST_RANDOM = {
        (byte)0xCF, (byte)0x21, (byte)0xAD, (byte)0x74, (byte)0xE5, (byte)0x9A, (byte)0x61, (byte)0x11,
        (byte)0xBE, (byte)0x1D, (byte)0x8C, (byte)0x02, (byte)0x1E, (byte)0x65, (byte)0xB8, (byte)0x91,
        (byte)0xC2, (byte)0xA2, (byte)0x11, (byte)0x16, (byte)0x7A, (byte)0xBB, (byte)0x8C, (byte)0x5E,
        (byte)0x07, (byte)0x9E, (byte)0x09, (byte)0xE2, (byte)0xC8, (byte)0xA8, (byte)0x33, (byte)0x9C
    };

    /** What, if anything, to corrupt in the second ClientHello on its way to the server. */
    private static final int MANGLE_NONE = 0;
    private static final int MANGLE_COOKIE = 1;
    private static final int MANGLE_RANDOM = 2;

    public void testClientServer() throws Exception
    {
        Harness harness = new Harness();

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        assertTrue("client cipher suite is not a TLS 1.3 suite: " + harness.clientCipherSuite,
            isTLSv13CipherSuite(harness.clientCipherSuite));
        assertTrue("server cipher suite is not a TLS 1.3 suite: " + harness.serverCipherSuite,
            isTLSv13CipherSuite(harness.serverCipherSuite));
        assertEquals("cipher suites differ", harness.clientCipherSuite, harness.serverCipherSuite);

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));

        checkClientHello(harness.clientRecords());
        checkServerHello(harness.serverRecords());

        checkUnifiedHeadersAfterHello(harness.clientRecords(), "client");
        checkUnifiedHeadersAfterHello(harness.serverRecords(), "server");

        checkEpochProgression(harness.clientRecords(), "client");
        checkEpochProgression(harness.serverRecords(), "server");
    }

    /**
     * RFC 9147 5.8.1. The client's final flight is dropped once, so the server retransmits its own flight
     * under the handshake traffic keys and the client must answer with a retransmitted Finished at the epoch
     * the server can still read. Without the record layer retaining the handshake epoch for reading, the
     * retransmitted server flight is discarded and the handshake never completes.
     */
    public void testClientServerWithClientFinishedLost() throws Exception
    {
        Harness harness = new Harness();
        harness.dropFirstClientEpoch2Datagram = true;

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));

        assertTrue("the client's final flight was not dropped", harness.dropped > 0);

        int clientEpoch2Records = countRecordsAtEpoch(harness.clientRecords(), 2);
        assertTrue("the client did not retransmit its final flight (epoch 2 records: " + clientEpoch2Records
            + ")", clientEpoch2Records >= 2);

        checkUnifiedHeadersAfterHello(harness.clientRecords(), "client");

        /*
         * The Finished still goes out at the handshake epoch first, and the retransmission of it arrives after
         * the client has moved on to epoch 3 - which is the whole point: the write epoch is not wound back, so
         * the retransmission is addressed to the retained handshake epoch while application data continues at
         * the application epoch.
         */
        assertEquals("the client's first protected record was not at the handshake epoch", 2,
            firstProtectedEpoch(harness.clientRecords()));
        assertTrue("the client did not retransmit at the handshake epoch after reaching epoch 3",
            lastProtectedEpoch(harness.clientRecords()) == 3
                && epochSequence(harness.clientRecords()).indexOf("323") >= 0);
    }

    /**
     * RFC 9147 5.8.1. The server's answer to a retransmission of the client's final flight is another ACK, and
     * a reordering reaches it where a duplicate cannot: the client's first Finished datagram is held until it
     * has sent a second, so the server completes on the second copy and then reads the first at a lower,
     * never-seen epoch-2 sequence number, which its replay window has no reason to discard.
     * <p>
     * The counts are of the server's protected records taken before any application data is sent, so each one
     * is an ACK: one for the final flight in the baseline, a second for the retransmission here. An
     * unauthenticated epoch-0 handshake record injected at the server afterwards must draw no ACK at all - the
     * server retains only the handshake epoch for reading, not the plaintext epoch the client needs.
     * </p>
     */
    public void testServerAcksReorderedFinalFlight() throws Exception
    {
        Harness baseline = new Harness();
        baseline.probeServerAckPath = true;

        baseline.run(16);

        assertNotNull("no application data echoed back", baseline.echo);
        assertEquals("the server sent more than the one ACK of the final flight", 1,
            baseline.serverEpoch3AfterHandshake);

        Harness harness = new Harness();
        harness.holdFirstClientEpoch2Datagram = true;
        harness.probeServerAckPath = true;

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        assertTrue("the client's final flight was not reordered", harness.reordered > 0);

        assertTrue("the server did not ACK the reordered retransmission of the final flight (protected records: "
            + harness.serverEpoch3AfterHandshake + ")", harness.serverEpoch3AfterHandshake >= 2);

        assertEquals("an unauthenticated epoch-0 handshake record drew an answer from the server",
            harness.serverEpoch3AfterHandshake, harness.serverEpoch3AfterInjection);

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));
    }

    /**
     * The ACK-driven retransmission of RFC 9147 7 over a lossy path, in both directions.
     */
    public void testClientServerWithPacketLoss() throws Exception
    {
        Harness harness = new Harness();
        harness.loss = new UnreliableDatagramTransportFactory(new Random(0x13131313L), 10, 10);

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));
    }

    /**
     * RFC 9147 5.1. The server's denial-of-service countermeasure for DTLS 1.3 is a HelloRetryRequest with a
     * "cookie" extension, not a HelloVerifyRequest. The handshake must complete after the retry, and the proof
     * that it did so over the right transcript is the Finished verification: RFC 8446 4.4.1 replaces the first
     * ClientHello with a synthetic "message_hash" message, and if either peer computed that substitution
     * differently the verify_data would not match and the handshake would have failed with "decrypt_error".
     * The verify data of each side is compared against what the other side computed for it, so a transcript
     * that merely happened to agree on something wrong is still caught by
     * {@link #testSecondClientHelloEchoesTheCookie}'s check of the bytes on the wire.
     */
    public void testClientServerWithHelloRetryRequest() throws Exception
    {
        Harness harness = new Harness();
        harness.forceHelloRetryRequest = true;

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        assertEquals("cipher suites differ", harness.clientCipherSuite, harness.serverCipherSuite);
        assertTrue("client cipher suite is not a TLS 1.3 suite: " + harness.clientCipherSuite,
            isTLSv13CipherSuite(harness.clientCipherSuite));

        // The retry really happened: two ClientHellos out, a HelloRetryRequest and then a ServerHello back
        Vector clientHellos = handshakeBodies(harness.clientRecords(), HandshakeType.client_hello);
        Vector serverHellos = handshakeBodies(harness.serverRecords(), HandshakeType.server_hello);

        assertEquals("number of ClientHellos sent", 2, clientHellos.size());
        assertEquals("number of ServerHellos received", 2, serverHellos.size());

        assertTrue("the server's first answer was not a HelloRetryRequest",
            isHelloRetryRequest((byte[])serverHellos.elementAt(0)));
        assertFalse("the server's second answer was another HelloRetryRequest",
            isHelloRetryRequest((byte[])serverHellos.elementAt(1)));

        /*
         * Finished verification succeeded on both sides: each peer's own verify_data is what the other peer
         * expected of it. Both are computed over the transcript that begins with the synthetic "message_hash".
         */
        assertNotNull("client has no Finished verify data", harness.clientLocalVerifyData);
        assertNotNull("server has no Finished verify data", harness.serverLocalVerifyData);

        assertTrue("the server did not verify the client's Finished over the same transcript",
            Arrays.areEqual(harness.clientLocalVerifyData, harness.serverPeerVerifyData));
        assertTrue("the client did not verify the server's Finished over the same transcript",
            Arrays.areEqual(harness.serverLocalVerifyData, harness.clientPeerVerifyData));

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));

        /*
         * RFC 9147 5.3 and 4. Both ClientHellos and both of the server's hellos are unprotected epoch-0
         * plaintext records; everything after them carries the unified header.
         */
        checkPlaintextHelloRecords(harness.clientRecords(), 2, "client");
        checkPlaintextHelloRecords(harness.serverRecords(), 2, "server");

        checkEpochProgression(harness.clientRecords(), "client");
        checkEpochProgression(harness.serverRecords(), "server");
    }

    /**
     * The first 'count' records of a side are unprotected epoch-0 plaintext hellos, and every record after
     * them is a DTLS 1.3 unified-header record (RFC 9147 4).
     */
    private void checkPlaintextHelloRecords(Vector records, int count, String side)
    {
        assertTrue(side + " sent fewer than " + count + " records", records.size() > count);

        for (int i = 0; i < count; ++i)
        {
            Record record = (Record)records.elementAt(i);

            assertFalse(side + " record " + i + " used the DTLS 1.3 unified header", record.isUnified());
            assertEquals(side + " record " + i + " content type", ContentType.handshake,
                record.getContentType());
            assertEquals(side + " record " + i + " epoch", 0, record.getPlaintextEpoch());
        }

        for (int i = count; i < records.size(); ++i)
        {
            Record record = (Record)records.elementAt(i);

            assertTrue(side + " record " + i + " is not a DTLS 1.3 unified-header record (first byte 0x"
                + Integer.toHexString(record.getFirstByte()) + ")", record.isUnified());
        }
    }

    /**
     * The cookie exchange over a lossy path. RFC 9147 5.8.1 retransmits each handshake fragment at the epoch
     * it was first sent under, and the flight bookkeeping is reset at each flight boundary: a cookie exchange
     * adds two of those boundaries on each side (the first ClientHello, then the HelloRetryRequest, then the
     * second ClientHello), so a retransmission after the retry must still find the right message. Loss is what
     * makes that machinery run at all, which is why this is a separate test from the clean one.
     */
    public void testClientServerWithHelloRetryRequestAndPacketLoss() throws Exception
    {
        Harness harness = new Harness();
        harness.forceHelloRetryRequest = true;
        harness.loss = new UnreliableDatagramTransportFactory(new Random(0x5AC00C1EL), 10, 10);

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        assertTrue("the server did not send a HelloRetryRequest", hasHelloRetryRequest(harness.serverRecords()));

        assertTrue("the server did not verify the client's Finished over the same transcript",
            Arrays.areEqual(harness.clientLocalVerifyData, harness.serverPeerVerifyData));
        assertTrue("the client did not verify the server's Finished over the same transcript",
            Arrays.areEqual(harness.serverLocalVerifyData, harness.clientPeerVerifyData));

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));

        /*
         * Every ClientHello and every (Hello)ServerHello, original or retransmitted, was sent at epoch 0.
         */
        checkHelloEpochs(harness.clientRecords(), HandshakeType.client_hello, "client");
        checkHelloEpochs(harness.serverRecords(), HandshakeType.server_hello, "server");
    }

    private static boolean hasHelloRetryRequest(Vector records)
    {
        Vector serverHellos = handshakeBodies(records, HandshakeType.server_hello);

        for (int i = 0; i < serverHellos.size(); ++i)
        {
            if (isHelloRetryRequest((byte[])serverHellos.elementAt(i)))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * RFC 9147 6.1. Every record carrying a message of the given handshake type was an unprotected epoch-0
     * plaintext record, retransmissions included - the epoch a fragment is retransmitted at is the one it was
     * first sent at, and for the hellos of a cookie exchange that is always 0.
     */
    private void checkHelloEpochs(Vector records, short msgType, String side)
    {
        int seen = 0;

        for (int i = 0; i < records.size(); ++i)
        {
            Record record = (Record)records.elementAt(i);
            if (record.isUnified() || ContentType.handshake != record.getContentType())
            {
                continue;
            }

            byte[] fragment = record.getFragment();
            if (fragment.length < MESSAGE_HEADER_LENGTH || msgType != (fragment[0] & 0xFF))
            {
                continue;
            }

            assertEquals(side + " record " + i + " epoch", 0, record.getPlaintextEpoch());
            ++seen;
        }

        assertTrue("no " + side + " hello records of type " + msgType, seen > 0);
    }

    /**
     * RFC 8446 4.2.2. "When sending the new ClientHello, the client MUST copy the contents of the extension
     * received in the HelloRetryRequest into a "cookie" extension in the new ClientHello." Read off the wire
     * in both directions, so that a client which echoed something else - or nothing - fails here even though
     * this server would accept it.
     * <p>
     * RFC 9147 5.3 also keeps the ClientHello's 'legacy_cookie' field for backwards compatibility only: a
     * DTLS 1.3 client writes it empty and a DTLS 1.3 server ignores it.
     * </p>
     */
    public void testSecondClientHelloEchoesTheCookie() throws Exception
    {
        Harness harness = new Harness();
        harness.forceHelloRetryRequest = true;

        harness.run(16);

        assertNotNull("no application data echoed back", harness.echo);

        Vector clientHellos = handshakeBodies(harness.clientRecords(), HandshakeType.client_hello);
        Vector serverHellos = handshakeBodies(harness.serverRecords(), HandshakeType.server_hello);

        assertEquals("number of ClientHellos sent", 2, clientHellos.size());
        assertTrue("the server's first answer was not a HelloRetryRequest",
            isHelloRetryRequest((byte[])serverHellos.elementAt(0)));

        byte[] issuedCookie = serverHelloCookie((byte[])serverHellos.elementAt(0));
        assertNotNull("the HelloRetryRequest carried no cookie extension", issuedCookie);
        assertTrue("the HelloRetryRequest cookie was empty", issuedCookie.length > 0);

        assertNull("the first ClientHello carried a cookie extension",
            clientHelloCookie((byte[])clientHellos.elementAt(0)));

        byte[] echoedCookie = clientHelloCookie((byte[])clientHellos.elementAt(1));
        assertNotNull("the second ClientHello carried no cookie extension", echoedCookie);
        assertTrue("the second ClientHello did not echo the cookie exactly",
            Arrays.areEqual(issuedCookie, echoedCookie));

        assertEquals("the first ClientHello's legacy_cookie was not empty", 0,
            clientHelloLegacyCookie((byte[])clientHellos.elementAt(0)).length);
        assertEquals("the second ClientHello's legacy_cookie was not empty", 0,
            clientHelloLegacyCookie((byte[])clientHellos.elementAt(1)).length);
    }

    /**
     * RFC 8446 4.1.4. "If a client receives a second HelloRetryRequest in the same connection (i.e., where the
     * ClientHello was itself in response to a HelloRetryRequest), it MUST abort the handshake with an
     * "unexpected_message" alert."
     * <p>
     * The second HelloRetryRequest is manufactured on the path rather than by the server, which will not send
     * one: the client's second ClientHello is swallowed and the server's own HelloRetryRequest record is
     * played back to the client instead, with a fresh record sequence number and the next handshake
     * message_seq so that nothing discards it as a duplicate. That is precisely what an attacker able to put a
     * datagram on the path can do, since these records are unprotected epoch-0 plaintext.
     * </p>
     */
    public void testSecondHelloRetryRequestRejected() throws Exception
    {
        Harness harness = new Harness();
        harness.forceHelloRetryRequest = true;
        harness.replaySecondHelloRetryRequest = true;

        try
        {
            harness.run(16);

            fail("expected the client to abort on a second HelloRetryRequest");
        }
        catch (TlsFatalAlert fatalAlert)
        {
            assertEquals("alert for a second HelloRetryRequest", AlertDescription.unexpected_message,
                fatalAlert.getAlertDescription());
        }

        assertTrue("the second HelloRetryRequest was never played back", harness.replayed > 0);
    }

    /**
     * RFC 8446 4.2.2. The second ClientHello must echo the cookie exactly, and a server that accepted anything
     * else would have no way to tell its own HelloRetryRequest's answer from an unrelated ClientHello. One byte
     * of the echoed cookie is flipped on the path, so the client is well-behaved and only the server's check
     * can catch it.
     */
    public void testSecondClientHelloWithAMangledCookieRejected() throws Exception
    {
        Harness harness = new Harness();
        harness.forceHelloRetryRequest = true;
        harness.mangleSecondClientHello = MANGLE_COOKIE;

        try
        {
            harness.run(16);

            fail("expected the server to abort on a mangled cookie");
        }
        catch (TlsFatalAlertReceived fatalAlert)
        {
            assertEquals("alert for a second ClientHello that did not echo the cookie",
                AlertDescription.illegal_parameter, fatalAlert.getAlertDescription());
        }

        assertTrue("the second ClientHello was never mangled", harness.mangled > 0);
    }

    /**
     * RFC 8446 4.1.2. "the client MUST send the same ClientHello without modification, except as follows"
     * - and 'random' is not on that list. One byte of it is flipped on the path, which must be refused rather
     * than quietly accepted as the answer to the HelloRetryRequest.
     */
    public void testSecondClientHelloThatDidNotRepeatTheFirstRejected() throws Exception
    {
        Harness harness = new Harness();
        harness.forceHelloRetryRequest = true;
        harness.mangleSecondClientHello = MANGLE_RANDOM;

        try
        {
            harness.run(16);

            fail("expected the server to abort on a second ClientHello that changed 'random'");
        }
        catch (TlsFatalAlertReceived fatalAlert)
        {
            assertEquals("alert for a second ClientHello that did not repeat the first",
                AlertDescription.illegal_parameter, fatalAlert.getAlertDescription());
        }

        assertTrue("the second ClientHello was never mangled", harness.mangled > 0);
    }

    /** RFC 8446 4.1.3. A ServerHello body whose 'random' is the HelloRetryRequest value. */
    private static boolean isHelloRetryRequest(byte[] serverHelloBody)
    {
        return Arrays.areEqual(HELLO_RETRY_REQUEST_RANDOM,
            Arrays.copyOfRange(serverHelloBody, 2, 2 + 32));
    }

    /**
     * The bodies of every unfragmented handshake message of the given type carried by the plaintext records,
     * in order. A ClientHello or ServerHello always fits one record at this MTU, so a fragmented one would be
     * a defect and is deliberately not reassembled here.
     */
    private static Vector handshakeBodies(Vector records, short msgType)
    {
        Vector bodies = new Vector();

        for (int i = 0; i < records.size(); ++i)
        {
            Record record = (Record)records.elementAt(i);
            if (record.isUnified() || ContentType.handshake != record.getContentType())
            {
                continue;
            }

            byte[] fragment = record.getFragment();

            int pos = 0;
            while (pos + MESSAGE_HEADER_LENGTH <= fragment.length)
            {
                int length = readUint24(fragment, pos + 1);
                int fragmentOffset = readUint24(fragment, pos + 6);
                int fragmentLength = readUint24(fragment, pos + 9);

                if (pos + MESSAGE_HEADER_LENGTH + fragmentLength > fragment.length)
                {
                    break;
                }

                if (msgType == (fragment[pos] & 0xFF) && 0 == fragmentOffset && length == fragmentLength)
                {
                    bodies.addElement(Arrays.copyOfRange(fragment, pos + MESSAGE_HEADER_LENGTH,
                        pos + MESSAGE_HEADER_LENGTH + fragmentLength));
                }

                pos += MESSAGE_HEADER_LENGTH + fragmentLength;
            }
        }

        return bodies;
    }

    /** RFC 9147 5.3. The ClientHello's 'legacy_cookie' field, which a DTLS 1.3 client writes empty. */
    private static byte[] clientHelloLegacyCookie(byte[] body)
    {
        int pos = 2 + 32;
        pos += 1 + (body[pos] & 0xFF);

        int cookieLength = body[pos] & 0xFF;
        return Arrays.copyOfRange(body, pos + 1, pos + 1 + cookieLength);
    }

    /** The contents of the ClientHello's "cookie" extension (RFC 8446 4.2.2), or null if it has none. */
    private static byte[] clientHelloCookie(byte[] body)
    {
        int valueOff = clientHelloCookieValueOffset(body, 0);
        if (valueOff < 0)
        {
            return null;
        }

        return Arrays.copyOfRange(body, valueOff, valueOff + readUint16(body, valueOff - 2));
    }

    /**
     * The offset within 'buf' of the first byte of the cookie carried by the "cookie" extension of the
     * ClientHello whose body begins at 'bodyOff', or -1 if there is no such extension. Offset-based rather
     * than copying, because the corruption tests rewrite the cookie in place in a datagram.
     */
    private static int clientHelloCookieValueOffset(byte[] buf, int bodyOff)
    {
        int pos = bodyOff + 2 + 32;
        // legacy_session_id
        pos += 1 + (buf[pos] & 0xFF);
        // legacy_cookie
        pos += 1 + (buf[pos] & 0xFF);
        // cipher_suites
        pos += 2 + readUint16(buf, pos);
        // legacy_compression_methods
        pos += 1 + (buf[pos] & 0xFF);

        if (pos + 2 > buf.length)
        {
            return -1;
        }

        int end = pos + 2 + readUint16(buf, pos);
        pos += 2;

        while (pos + 4 <= end)
        {
            int extensionType = readUint16(buf, pos);
            int extensionLength = readUint16(buf, pos + 2);
            pos += 4;

            if (ExtensionType.cookie == extensionType)
            {
                // The extension data is opaque cookie<1..2^16-1>, so skip its own length prefix
                return pos + 2;
            }

            pos += extensionLength;
        }

        return -1;
    }

    /**
     * The offset within the datagram of the body of the first ClientHello it carries, or -1 if it carries
     * none. Only unprotected plaintext records are walked: a ClientHello is never anything else.
     */
    private static int findClientHelloBodyOffset(byte[] buf, int off, int len)
    {
        int pos = off;
        int end = off + len;

        while (pos + PLAINTEXT_HEADER_LENGTH <= end)
        {
            int firstByte = buf[pos] & 0xFF;
            if ((firstByte & UNIFIED_FIXED_BITS_MASK) == UNIFIED_FIXED_BITS)
            {
                return -1;
            }

            int recordLength = PLAINTEXT_HEADER_LENGTH + readUint16(buf, pos + 11);
            if (pos + recordLength > end)
            {
                return -1;
            }

            int fragment = pos + PLAINTEXT_HEADER_LENGTH;

            if (ContentType.handshake == firstByte
                && fragment + MESSAGE_HEADER_LENGTH <= end
                && HandshakeType.client_hello == (buf[fragment] & 0xFF))
            {
                return fragment + MESSAGE_HEADER_LENGTH;
            }

            pos += recordLength;
        }

        return -1;
    }

    /** The contents of the ServerHello's "cookie" extension (RFC 8446 4.2.2), or null if it has none. */
    private static byte[] serverHelloCookie(byte[] body)
    {
        int pos = 2 + 32;
        // legacy_session_id_echo
        pos += 1 + (body[pos] & 0xFF);
        // cipher_suite and legacy_compression_method
        pos += 3;

        return findCookieExtension(body, pos);
    }

    /**
     * Walks the extensions block beginning at 'pos' (a uint16 length followed by type/length/data triples) and
     * decodes the "cookie" extension's own opaque&lt;1..2^16-1&gt; body.
     */
    private static byte[] findCookieExtension(byte[] body, int pos)
    {
        if (pos + 2 > body.length)
        {
            return null;
        }

        int end = pos + 2 + readUint16(body, pos);
        pos += 2;

        while (pos + 4 <= end)
        {
            int extensionType = readUint16(body, pos);
            int extensionLength = readUint16(body, pos + 2);
            pos += 4;

            if (ExtensionType.cookie == extensionType)
            {
                return Arrays.copyOfRange(body, pos + 2, pos + extensionLength);
            }

            pos += extensionLength;
        }

        return null;
    }

    private static boolean isTLSv13CipherSuite(int cipherSuite)
    {
        switch (cipherSuite)
        {
        case CipherSuite.TLS_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_AES_128_CCM_SHA256:
        case CipherSuite.TLS_AES_128_GCM_SHA256:
        case CipherSuite.TLS_AES_256_GCM_SHA384:
        case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            return true;
        default:
            return false;
        }
    }

    /**
     * RFC 9147 5.3 and 5.2. The ClientHello is a plaintext record at epoch 0, and carries the full 12-byte
     * DTLS handshake message header on the wire - which is exactly what the DTLS 1.3 transcript must
     * <em>not</em> include (RFC 9147 5.2), so this pins the two encodings apart.
     */
    private void checkClientHello(Vector records) throws IOException
    {
        assertFalse("no client records captured", records.isEmpty());

        Record first = (Record)records.elementAt(0);

        assertFalse("the ClientHello used the DTLS 1.3 unified header", first.isUnified());
        assertEquals("ClientHello record content type", ContentType.handshake, first.getContentType());
        assertEquals("ClientHello record epoch", 0, first.getPlaintextEpoch());

        byte[] fragment = first.getFragment();
        assertTrue("ClientHello record too short for a handshake message header",
            fragment.length >= MESSAGE_HEADER_LENGTH);

        assertEquals("handshake message type", HandshakeType.client_hello, fragment[0] & 0xFF);

        int length = readUint24(fragment, 1);
        int messageSeq = readUint16(fragment, 4);
        int fragmentOffset = readUint24(fragment, 6);
        int fragmentLength = readUint24(fragment, 9);

        assertEquals("ClientHello message_seq", 0, messageSeq);
        assertEquals("ClientHello fragment_offset", 0, fragmentOffset);
        assertEquals("ClientHello fragment_length", length, fragmentLength);
        assertEquals("ClientHello record length", MESSAGE_HEADER_LENGTH + fragmentLength, fragment.length);
    }

    /** RFC 9147 5.3. The ServerHello is still a plaintext record, with legacy_record_version 0xfefd. */
    private void checkServerHello(Vector records) throws IOException
    {
        assertFalse("no server records captured", records.isEmpty());

        Record first = (Record)records.elementAt(0);

        assertFalse("the ServerHello used the DTLS 1.3 unified header", first.isUnified());
        assertEquals("ServerHello record content type", ContentType.handshake, first.getContentType());
        assertEquals("ServerHello record epoch", 0, first.getPlaintextEpoch());
        assertEquals("ServerHello legacy_record_version", ProtocolVersion.DTLSv12, first.getPlaintextVersion());

        assertEquals("handshake message type", HandshakeType.server_hello, first.getFragment()[0] & 0xFF);
    }

    /**
     * RFC 9147 4. Every record after the initial plaintext hello must be a DTLSCiphertext with the unified
     * header, whose first byte has the fixed bits 001 in its top three bits.
     */
    private void checkUnifiedHeadersAfterHello(Vector records, String side)
    {
        int unified = 0;

        for (int i = 1; i < records.size(); ++i)
        {
            Record record = (Record)records.elementAt(i);

            assertTrue(side + " record " + i + " is not a DTLS 1.3 unified-header record (first byte 0x"
                + Integer.toHexString(record.getFirstByte()) + ")", record.isUnified());

            assertEquals(side + " record " + i + " unified header fixed bits", UNIFIED_FIXED_BITS,
                record.getFirstByte() & UNIFIED_FIXED_BITS_MASK);

            ++unified;
        }

        assertTrue("no unified-header records sent by the " + side, unified > 0);
    }

    /**
     * RFC 9147 6.1. Epoch 1 is reserved for early data, so the handshake traffic keys are epoch 2 and the
     * application traffic keys epoch 3. Nothing may be sent at epoch 3 before the Finished has gone out at
     * epoch 2, and the connection must actually reach epoch 3.
     */
    private void checkEpochProgression(Vector records, String side)
    {
        boolean seenEpoch2 = false;
        boolean seenEpoch3 = false;

        for (int i = 0; i < records.size(); ++i)
        {
            Record record = (Record)records.elementAt(i);
            if (!record.isUnified())
            {
                continue;
            }

            int epochBits = record.getFirstByte() & UNIFIED_EPOCH_BITS_MASK;

            if (2 == epochBits)
            {
                assertFalse(side + " sent a handshake-epoch record after moving to epoch 3", seenEpoch3);
                seenEpoch2 = true;
            }
            else if (3 == epochBits)
            {
                assertTrue(side + " reached epoch 3 without sending anything at epoch 2", seenEpoch2);
                seenEpoch3 = true;
            }
            else
            {
                fail(side + " sent a protected record with unexpected epoch bits " + epochBits);
            }
        }

        assertTrue(side + " sent nothing at the handshake epoch", seenEpoch2);
        assertTrue(side + " never reached epoch 3", seenEpoch3);
    }

    /** The epoch bits of each protected record, in order, as digits. */
    private static String epochSequence(Vector records)
    {
        StringBuffer sb = new StringBuffer();

        for (int i = 0; i < records.size(); ++i)
        {
            Record record = (Record)records.elementAt(i);
            if (record.isUnified())
            {
                sb.append((char)('0' + (record.getFirstByte() & UNIFIED_EPOCH_BITS_MASK)));
            }
        }

        return sb.toString();
    }

    private static int firstProtectedEpoch(Vector records)
    {
        String epochs = epochSequence(records);
        return epochs.length() < 1 ? -1 : epochs.charAt(0) - '0';
    }

    private static int lastProtectedEpoch(Vector records)
    {
        String epochs = epochSequence(records);
        return epochs.length() < 1 ? -1 : epochs.charAt(epochs.length() - 1) - '0';
    }

    private static int countRecordsAtEpoch(Vector records, int epoch)
    {
        int count = 0;

        for (int i = 0; i < records.size(); ++i)
        {
            Record record = (Record)records.elementAt(i);
            if (record.isUnified() && (record.getFirstByte() & UNIFIED_EPOCH_BITS_MASK) == (epoch & 0x03))
            {
                ++count;
            }
        }

        return count;
    }

    private static int readUint16(byte[] buf, int off)
    {
        return ((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF);
    }

    private static int readUint24(byte[] buf, int off)
    {
        return ((buf[off] & 0xFF) << 16) | ((buf[off + 1] & 0xFF) << 8) | (buf[off + 2] & 0xFF);
    }

    /**
     * The harness drives one complete handshake and one application-data exchange, recording every record
     * that crossed the client's transport in either direction.
     */
    static class Harness
    {
        boolean dropFirstClientEpoch2Datagram = false;
        boolean holdFirstClientEpoch2Datagram = false;
        boolean probeServerAckPath = false;
        boolean forceHelloRetryRequest = false;
        boolean replaySecondHelloRetryRequest = false;
        int mangleSecondClientHello = MANGLE_NONE;
        UnreliableDatagramTransportFactory loss = null;

        ProtocolVersion clientVersion = null;
        ProtocolVersion serverVersion = null;
        int clientCipherSuite = -1;
        int serverCipherSuite = -1;
        byte[] request = null;
        byte[] echo = null;
        int dropped = 0;
        int reordered = 0;
        int replayed = 0;
        int mangled = 0;

        byte[] clientLocalVerifyData = null;
        byte[] clientPeerVerifyData = null;
        byte[] serverLocalVerifyData = null;
        byte[] serverPeerVerifyData = null;

        // Counts of the server's protected (epoch 3) records, taken while no application data is in flight
        int serverEpoch3AfterHandshake = -1;
        int serverEpoch3AfterInjection = -1;

        private RecordingDatagramTransport recording = null;
        private DatagramTransport rawClientTransport = null;

        Vector clientRecords()
        {
            return recording.getSentRecords();
        }

        Vector serverRecords()
        {
            return recording.getReceivedRecords();
        }

        void run(int dataLength) throws Exception
        {
            MockDTLSClient client = new MockDTLSClient(null)
            {
                protected ProtocolVersion[] getSupportedVersions()
                {
                    return ProtocolVersion.DTLSv13.only();
                }

                public void notifyServerVersion(ProtocolVersion version) throws IOException
                {
                    super.notifyServerVersion(version);

                    clientVersion = version;
                }

                public void notifyHandshakeComplete() throws IOException
                {
                    super.notifyHandshakeComplete();

                    SecurityParameters sp = context.getSecurityParametersConnection();

                    clientCipherSuite = sp.getCipherSuite();
                    clientLocalVerifyData = sp.getLocalVerifyData();
                    clientPeerVerifyData = sp.getPeerVerifyData();
                }
            };
            client.setHandshakeTimeoutMillis(HANDSHAKE_TIMEOUT_MILLIS);

            MockDTLSServer server = new MockDTLSServer()
            {
                protected ProtocolVersion[] getSupportedVersions()
                {
                    return ProtocolVersion.DTLSv13.only();
                }

                public int getHandshakeTimeoutMillis()
                {
                    return HANDSHAKE_TIMEOUT_MILLIS;
                }

                public int[] getSupportedGroups() throws IOException
                {
                    if (!forceHelloRetryRequest)
                    {
                        return super.getSupportedGroups();
                    }

                    /*
                     * RFC 8446 4.1.4 and 4.2.8. The client sends a key share only for its single most
                     * preferred group (x25519 here), so a server that will only use secp384r1 has no usable
                     * share and must answer with a HelloRetryRequest naming it. That is the one reason this
                     * implementation sends a HelloRetryRequest, and the cookie rides along with it.
                     */
                    return new int[]{ NamedGroup.secp384r1 };
                }

                public ProtocolVersion getServerVersion() throws IOException
                {
                    ProtocolVersion version = super.getServerVersion();

                    serverVersion = version;

                    return version;
                }

                public void notifyHandshakeComplete() throws IOException
                {
                    super.notifyHandshakeComplete();

                    SecurityParameters sp = context.getSecurityParametersConnection();

                    serverCipherSuite = sp.getCipherSuite();
                    serverLocalVerifyData = sp.getLocalVerifyData();
                    serverPeerVerifyData = sp.getPeerVerifyData();
                }
            };

            MockDatagramAssociation network = new MockDatagramAssociation(1500);

            DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

            ServerThread serverThread = new ServerThread(serverProtocol, server, network.getServer());
            serverThread.setDaemon(true);
            serverThread.start();

            this.rawClientTransport = network.getClient();

            DatagramTransport clientTransport = rawClientTransport;

            if (null != loss)
            {
                clientTransport = loss.create(clientTransport);
            }

            this.recording = new RecordingDatagramTransport(clientTransport);
            recording.dropFirstEpoch2Datagram = dropFirstClientEpoch2Datagram;
            recording.holdFirstEpoch2Datagram = holdFirstClientEpoch2Datagram;
            recording.replaySecondHelloRetryRequest = replaySecondHelloRetryRequest;
            recording.mangleSecondClientHello = mangleSecondClientHello;

            try
            {
                DTLSTransport dtlsClient = new DTLSClientProtocol().connect(client, recording);

                if (probeServerAckPath)
                {
                    probeServerAckPath(dtlsClient);
                }

                this.request = new byte[dataLength];
                Arrays.fill(request, (byte)0x5A);

                byte[] buf = new byte[dtlsClient.getReceiveLimit()];

                /*
                 * The request is re-sent on each attempt: with loss, the server may still be completing its
                 * own handshake when the client's first application record arrives at an epoch the server
                 * cannot yet read, and that record is legitimately discarded.
                 */
                for (int attempt = 0; attempt < 20 && null == echo; ++attempt)
                {
                    dtlsClient.send(request, 0, request.length);

                    int length = dtlsClient.receive(buf, 0, buf.length, 500);
                    if (length >= 0)
                    {
                        this.echo = Arrays.copyOfRange(buf, 0, length);
                    }
                }

                dtlsClient.close();
            }
            finally
            {
                this.dropped = recording.getDropped();
                this.reordered = recording.getReordered();
                this.replayed = recording.getReplayed();
                this.mangled = recording.getMangled();

                serverThread.shutdown();
            }
        }

        /**
         * Counts the server's protected records once the handshake has completed and again after an
         * unauthenticated epoch-0 handshake record has been injected. No application data has been sent at
         * either point, so every protected record the server has sent is an ACK (RFC 9147 7.1): the first
         * count is the ACK of the final flight plus any answer to the reordered retransmission of it, and the
         * second shows whether the injected record drew an answer of its own.
         */
        private void probeServerAckPath(DTLSTransport dtlsClient) throws IOException
        {
            /*
             * connect() returns as soon as the client has written its Finished, so the server has not
             * necessarily completed yet - and in the reordering case it has not even retransmitted its own
             * flight, which is what provokes the second copy of the Finished.
             */
            int expected = holdFirstClientEpoch2Datagram ? 2 : 1;

            this.serverEpoch3AfterHandshake = drainServerEpoch3(dtlsClient, expected, 20000, 1500);

            injectPlaintextHandshakeRecord();

            // An answer to the injected record would be immediate, so a short wait is enough to rule one out
            this.serverEpoch3AfterInjection = drainServerEpoch3(dtlsClient, serverEpoch3AfterHandshake + 1, 2000,
                0);
        }

        /**
         * Pumps the client's receive path until the server has sent the expected number of protected records
         * (or the deadline passes), then keeps pumping for the settle period so that a record arriving after
         * the expected ones is still counted.
         *
         * @return the number of protected records the server had sent by the end.
         */
        private int drainServerEpoch3(DTLSTransport dtlsClient, int expected, int deadlineMillis, int settleMillis)
            throws IOException
        {
            byte[] buf = new byte[dtlsClient.getReceiveLimit()];

            long deadline = System.currentTimeMillis() + deadlineMillis;
            while (System.currentTimeMillis() < deadline
                && countRecordsAtEpoch(serverRecords(), 3) < expected)
            {
                dtlsClient.receive(buf, 0, buf.length, 200);
            }

            long settleDeadline = System.currentTimeMillis() + settleMillis;
            while (System.currentTimeMillis() < settleDeadline)
            {
                dtlsClient.receive(buf, 0, buf.length, 200);
            }

            return countRecordsAtEpoch(serverRecords(), 3);
        }

        /**
         * Sends the server a plaintext epoch-0 record with a handshake content type, imitating the client's
         * final flight (a Finished with the message_seq the real one had). It bypasses the client's record
         * layer entirely, which is exactly the position of anyone able to put a datagram on the path: epoch 0
         * is unauthenticated, so this record is forgeable by an off-path attacker who can guess the 5-tuple.
         */
        private void injectPlaintextHandshakeRecord() throws IOException
        {
            int bodyLength = 32;
            byte[] record = new byte[PLAINTEXT_HEADER_LENGTH + MESSAGE_HEADER_LENGTH + bodyLength];

            record[0] = (byte)ContentType.handshake;
            record[1] = (byte)0xFE;
            record[2] = (byte)0xFD;
            // epoch 0, sequence_number 1
            record[10] = (byte)1;
            record[11] = (byte)((MESSAGE_HEADER_LENGTH + bodyLength) >>> 8);
            record[12] = (byte)(MESSAGE_HEADER_LENGTH + bodyLength);

            int off = PLAINTEXT_HEADER_LENGTH;
            record[off] = (byte)HandshakeType.finished;
            record[off + 3] = (byte)bodyLength;
            // The client's final flight is its Finished, which follows its ClientHello as message_seq 1
            record[off + 5] = (byte)1;
            record[off + 11] = (byte)bodyLength;

            rawClientTransport.send(record, 0, record.length);
        }
    }

    static class ServerThread
        extends Thread
    {
        private final DTLSServerProtocol serverProtocol;
        private final TlsServer server;
        private final DatagramTransport serverTransport;
        private volatile boolean isShutdown = false;

        ServerThread(DTLSServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
            this.serverTransport = serverTransport;
        }

        public void run()
        {
            try
            {
                /*
                 * NOTE: Not the DTLSVerifier harness the DTLS 1.2 tests use: that issues a DTLS 1.2
                 * HelloVerifyRequest, which RFC 9147 5.1 has no place for in DTLS 1.3.
                 */
                DTLSTransport dtlsTransport = serverProtocol.accept(server, serverTransport);

                byte[] buf = new byte[dtlsTransport.getReceiveLimit()];
                while (!isShutdown)
                {
                    int length = dtlsTransport.receive(buf, 0, buf.length, 100);
                    if (length >= 0)
                    {
                        dtlsTransport.send(buf, 0, length);
                    }
                }
                dtlsTransport.close();
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }

        void shutdown()
            throws InterruptedException
        {
            if (!isShutdown)
            {
                isShutdown = true;
                this.join();
            }
        }
    }

    static class UnreliableDatagramTransportFactory
    {
        private final Random random;
        private final int percentPacketLossReceiving, percentPacketLossSending;

        UnreliableDatagramTransportFactory(Random random, int percentPacketLossReceiving,
            int percentPacketLossSending)
        {
            this.random = random;
            this.percentPacketLossReceiving = percentPacketLossReceiving;
            this.percentPacketLossSending = percentPacketLossSending;
        }

        DatagramTransport create(DatagramTransport transport)
        {
            return new UnreliableDatagramTransport(transport, random, percentPacketLossReceiving,
                percentPacketLossSending);
        }
    }

    /**
     * Records every record seen in either direction, and optionally drops the first datagram carrying a
     * record at the handshake epoch - which for the client is exactly its final flight.
     */
    static class RecordingDatagramTransport
        implements DatagramTransport
    {
        private final DatagramTransport transport;
        private final Vector sentRecords = new Vector();
        private final Vector receivedRecords = new Vector();

        boolean dropFirstEpoch2Datagram = false;
        boolean holdFirstEpoch2Datagram = false;
        boolean replaySecondHelloRetryRequest = false;
        int mangleSecondClientHello = MANGLE_NONE;

        private byte[] held = null;
        private byte[] capturedHelloRetryRequest = null;
        private byte[] injected = null;
        private int clientHellosSent = 0;
        private int dropped = 0;
        private int reordered = 0;
        private int replayed = 0;
        private int mangled = 0;

        RecordingDatagramTransport(DatagramTransport transport)
        {
            this.transport = transport;
        }

        Vector getSentRecords()
        {
            synchronized (sentRecords)
            {
                return new Vector(sentRecords);
            }
        }

        Vector getReceivedRecords()
        {
            synchronized (receivedRecords)
            {
                return new Vector(receivedRecords);
            }
        }

        int getDropped()
        {
            return dropped;
        }

        int getReordered()
        {
            return reordered;
        }

        int getReplayed()
        {
            return replayed;
        }

        int getMangled()
        {
            return mangled;
        }

        public int getReceiveLimit() throws IOException
        {
            return transport.getReceiveLimit();
        }

        public int getSendLimit() throws IOException
        {
            return transport.getSendLimit();
        }

        public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException
        {
            int length;

            byte[] replay = injected;
            if (null != replay && replay.length <= len)
            {
                this.injected = null;

                System.arraycopy(replay, 0, buf, off, replay.length);
                length = replay.length;
            }
            else
            {
                length = transport.receive(buf, off, len, waitMillis);
            }

            if (length > 0)
            {
                Vector records = parseRecords(buf, off, length);
                synchronized (receivedRecords)
                {
                    for (int i = 0; i < records.size(); ++i)
                    {
                        receivedRecords.addElement(records.elementAt(i));
                    }
                }

                if (replaySecondHelloRetryRequest && null == capturedHelloRetryRequest)
                {
                    this.capturedHelloRetryRequest = findHelloRetryRequestRecord(records);
                }
            }

            return length;
        }

        public void send(byte[] buf, int off, int len) throws IOException
        {
            Vector records = parseRecords(buf, off, len);

            // NOTE: Recorded even when dropped below - these are the records the client emitted
            synchronized (sentRecords)
            {
                for (int i = 0; i < records.size(); ++i)
                {
                    sentRecords.addElement(records.elementAt(i));
                }
            }

            if (replaySecondHelloRetryRequest || MANGLE_NONE != mangleSecondClientHello)
            {
                int clientHelloBodyOffset = findClientHelloBodyOffset(buf, off, len);
                if (clientHelloBodyOffset >= 0)
                {
                    ++clientHellosSent;

                    if (2 == clientHellosSent && replaySecondHelloRetryRequest
                        && null != capturedHelloRetryRequest)
                    {
                        /*
                         * Swallow the second ClientHello and answer it with the server's own HelloRetryRequest
                         * record instead, renumbered so that neither the record-layer replay window nor the
                         * handshake's message_seq bookkeeping can discard it as something already seen.
                         */
                        byte[] replay = Arrays.clone(capturedHelloRetryRequest);

                        // record sequence_number, a value the server has not used
                        replay[5] = (byte)0;
                        replay[9] = (byte)0x7F;
                        replay[10] = (byte)0xFF;

                        // handshake message_seq: the one after the server's real HelloRetryRequest
                        replay[PLAINTEXT_HEADER_LENGTH + 4] = (byte)0;
                        replay[PLAINTEXT_HEADER_LENGTH + 5] = (byte)1;

                        this.injected = replay;
                        ++replayed;

                        System.out.println("DTLS 1.3 test: replayed the HelloRetryRequest as a second one");
                        return;
                    }

                    /*
                     * NOTE: Every ClientHello from the second on, retransmissions included, so that a
                     * retransmission cannot arrive intact and let the handshake through after all.
                     */
                    if (clientHellosSent >= 2 && MANGLE_NONE != mangleSecondClientHello)
                    {
                        byte[] datagram = Arrays.copyOfRange(buf, off, off + len);
                        int bodyOffset = clientHelloBodyOffset - off;

                        int target = MANGLE_COOKIE == mangleSecondClientHello
                            ? clientHelloCookieValueOffset(datagram, bodyOffset)
                            : bodyOffset + 2;

                        if (target >= 0)
                        {
                            datagram[target] ^= (byte)0x01;
                            ++mangled;

                            System.out.println("DTLS 1.3 test: corrupted byte " + target
                                + " of the second ClientHello");
                        }

                        transport.send(datagram, 0, datagram.length);
                        return;
                    }
                }
            }

            if (dropFirstEpoch2Datagram && containsEpoch(records, 2))
            {
                dropFirstEpoch2Datagram = false;
                ++dropped;

                System.out.println("DTLS 1.3 test: dropped the client's " + len + " byte handshake-epoch flight");
                return;
            }

            if (containsEpoch(records, 2))
            {
                if (holdFirstEpoch2Datagram)
                {
                    /*
                     * Held rather than dropped: the peer stops retransmitting its own flight once this one
                     * arrives, so holding it until the client has sent a second copy is what delivers the two
                     * copies out of order - the later one first, then this one at a lower, never-seen sequence
                     * number, which the replay window cannot discard.
                     */
                    holdFirstEpoch2Datagram = false;
                    this.held = Arrays.copyOfRange(buf, off, off + len);

                    System.out.println("DTLS 1.3 test: held the client's " + len + " byte handshake-epoch flight");
                    return;
                }

                if (null != held)
                {
                    byte[] heldDatagram = held;
                    this.held = null;
                    ++reordered;

                    transport.send(buf, off, len);
                    transport.send(heldDatagram, 0, heldDatagram.length);

                    System.out.println("DTLS 1.3 test: released the held flight after its retransmission");
                    return;
                }
            }

            transport.send(buf, off, len);
        }

        public void close() throws IOException
        {
            transport.close();
        }

        /** The raw bytes of a plaintext record carrying a HelloRetryRequest, or null if there is none. */
        private static byte[] findHelloRetryRequestRecord(Vector records)
        {
            for (int i = 0; i < records.size(); ++i)
            {
                Record record = (Record)records.elementAt(i);
                if (!record.isUnified() && ContentType.handshake == record.getContentType())
                {
                    byte[] fragment = record.getFragment();
                    if (fragment.length >= MESSAGE_HEADER_LENGTH + 2 + 32
                        && HandshakeType.server_hello == (fragment[0] & 0xFF)
                        && isHelloRetryRequest(Arrays.copyOfRange(fragment, MESSAGE_HEADER_LENGTH,
                            fragment.length)))
                    {
                        return record.getBytes();
                    }
                }
            }
            return null;
        }

        private static boolean containsEpoch(Vector records, int epoch)
        {
            for (int i = 0; i < records.size(); ++i)
            {
                Record record = (Record)records.elementAt(i);
                if (record.isUnified() && (record.getFirstByte() & UNIFIED_EPOCH_BITS_MASK) == (epoch & 0x03))
                {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Splits a datagram into the records it carries - a flight is coalesced into as few datagrams as the MTU
     * allows, so one datagram is usually several records.
     */
    static Vector parseRecords(byte[] buf, int off, int len)
    {
        Vector records = new Vector();

        int pos = off;
        int end = off + len;

        while (pos < end)
        {
            int firstByte = buf[pos] & 0xFF;
            int recordLength;

            if ((firstByte & UNIFIED_FIXED_BITS_MASK) == UNIFIED_FIXED_BITS)
            {
                if ((firstByte & UNIFIED_FLAG_CID) != 0)
                {
                    // This implementation never writes a connection ID, so its length is not known here
                    throw new IllegalStateException("unexpected connection ID in a DTLS 1.3 record");
                }

                int headerLength = 1 + ((firstByte & UNIFIED_FLAG_SEQ16) != 0 ? 2 : 1)
                    + ((firstByte & UNIFIED_FLAG_LENGTH) != 0 ? 2 : 0);

                if ((firstByte & UNIFIED_FLAG_LENGTH) != 0)
                {
                    if (pos + headerLength > end)
                    {
                        break;
                    }
                    recordLength = headerLength + readUint16(buf, pos + headerLength - 2);
                }
                else
                {
                    recordLength = end - pos;
                }
            }
            else
            {
                if (pos + PLAINTEXT_HEADER_LENGTH > end)
                {
                    break;
                }
                recordLength = PLAINTEXT_HEADER_LENGTH + readUint16(buf, pos + 11);
            }

            if (recordLength < 1 || pos + recordLength > end)
            {
                break;
            }

            records.addElement(new Record(Arrays.copyOfRange(buf, pos, pos + recordLength)));

            pos += recordLength;
        }

        return records;
    }

    static class Record
    {
        private final byte[] record;

        Record(byte[] record)
        {
            this.record = record;
        }

        int getFirstByte()
        {
            return record[0] & 0xFF;
        }

        boolean isUnified()
        {
            return (getFirstByte() & UNIFIED_FIXED_BITS_MASK) == UNIFIED_FIXED_BITS;
        }

        short getContentType()
        {
            return (short)getFirstByte();
        }

        ProtocolVersion getPlaintextVersion()
        {
            return ProtocolVersion.get(record[1] & 0xFF, record[2] & 0xFF);
        }

        int getPlaintextEpoch()
        {
            return readUint16(record, 3);
        }

        /** The record exactly as it crossed the transport. */
        byte[] getBytes()
        {
            return Arrays.clone(record);
        }

        /** The plaintext fragment of an unprotected record. */
        byte[] getFragment()
        {
            return Arrays.copyOfRange(record, PLAINTEXT_HEADER_LENGTH, record.length);
        }
    }
}
