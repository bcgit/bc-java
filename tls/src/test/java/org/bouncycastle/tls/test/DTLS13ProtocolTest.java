package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Random;
import java.util.Vector;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSRequest;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DTLSVerifier;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SRTPProtectionProfile;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsFatalAlertReceived;
import org.bouncycastle.tls.TlsSRTPUtils;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.UseSRTPData;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

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

    /**
     * The MTU the handshakes here run at, and a smaller one at which the client's authenticated flight no
     * longer fits its records and has to be fragmented (RFC 9147 5.5). Both are above the 576-byte floor
     * RFC 9147 4.2 assumes for a path MTU estimate only in the first case: 512 is deliberately small.
     */
    private static final int DEFAULT_MTU = 1500;
    private static final int FRAGMENTING_MTU = 512;

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

    // NOTE: Test value only - would typically be the client's IP address
    private static final byte[] CLIENT_ID = Strings.toUTF8ByteArray("MockDtlsClient");

    /**
     * RFC 5705 2. Two exporter labels and the length of the material derived for each, so that a peer which
     * ignored the label - or derived one constant for everything - is distinguishable from one which did not.
     */
    private static final String EXPORTER_LABEL = "BC_DTLS13_TESTS_1";
    private static final String EXPORTER_LABEL_OTHER = "BC_DTLS13_TESTS_2";
    private static final int EXPORTER_LENGTH = 32;

    /**
     * RFC 5764 4.1.2. The protection profiles a 'useSrtp' client offers, most preferred first, and the MKI it
     * offers with them. The server deliberately selects the <em>last</em> of them rather than the first, so
     * that a client which reported a profile it had merely offered would not pass.
     */
    private static final int[] SRTP_PROTECTION_PROFILES = new int[]{ SRTPProtectionProfile.SRTP_AEAD_AES_128_GCM,
        SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80 };
    private static final byte[] SRTP_MKI = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04 };

    /**
     * RFC 5764 4.2. DTLS-SRTP takes its keying material from the RFC 5705 exporter under this label, with no
     * context, and for SRTP_AES128_CM_HMAC_SHA1_80 it needs a 16-byte key and a 14-byte salt per direction.
     */
    private static final String SRTP_EXPORTER_LABEL = "EXTRACTOR-dtls_srtp";
    private static final int SRTP_KEYING_MATERIAL_LENGTH = 2 * (16 + 14);

    /** What, if anything, to corrupt in the second ClientHello on its way to the server. */
    private static final int MANGLE_NONE = 0;
    private static final int MANGLE_COOKIE = 1;
    private static final int MANGLE_RANDOM = 2;

    /**
     * The plain baseline: a certificate-based DTLS 1.3 handshake with no CertificateRequest at all, which is
     * the shortest flight shape the protocol has and the one that leaves 'state.certificateRequest' null on
     * both peers. Every other test here has the server ask for a certificate, optionally or otherwise, so
     * without this one that branch would go unexercised.
     */
    public void testClientServer() throws Exception
    {
        Harness harness = new Harness();
        harness.serverCertReq = TlsTestConfig.SERVER_CERT_REQ_NONE;

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

        /*
         * No CertificateRequest was sent, so the client was never asked for credentials and the server never
         * saw a Certificate message of any kind - not even the empty one a declining client would send.
         */
        assertEquals("CertificateRequests the client was asked to answer", 0,
            harness.clientCertificateRequestsSeen);
        assertEquals("the client sent a certificate of its own", -1, harness.clientLocalCertChainLength);
        assertEquals("the server received a client Certificate message", -1, harness.serverPeerCertChainLength);

        checkClientHello(harness.clientRecords());
        checkServerHello(harness.serverRecords());

        checkUnifiedHeadersAfterHello(harness.clientRecords(), "client");
        checkUnifiedHeadersAfterHello(harness.serverRecords(), "server");

        checkEpochProgression(harness.clientRecords(), "client");
        checkEpochProgression(harness.serverRecords(), "server");
    }

    /**
     * RFC 8446 4.4.2 and 4.4.3. A mutually authenticated handshake: the server sends a CertificateRequest in
     * its flight, and the client answers with a Certificate carrying its chain plus a CertificateVerify over
     * the transcript through that Certificate.
     * <p>
     * The proof that the client's signature was computed over the transcript the server expects is that the
     * handshake completed at all: the server verifies the CertificateVerify against its own transcript hash
     * taken at the same cut point, and a mismatch is a fatal "decrypt_error" rather than a quiet pass - which
     * is what {@link #testClientServerWithACorruptedClientCertificateVerify} exercises in the other direction.
     * The Finished cross-check below then proves both peers' transcripts agree through the client's
     * Certificate and CertificateVerify as well.
     * </p>
     */
    public void testClientServerWithClientAuthentication() throws Exception
    {
        Harness harness = new Harness();
        harness.clientAuth = TlsTestConfig.CLIENT_AUTH_VALID;
        harness.serverCertReq = TlsTestConfig.SERVER_CERT_REQ_MANDATORY;

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        assertTrue("the client did not send a certificate of its own", harness.clientLocalCertChainLength > 0);
        assertTrue("the server did not receive a client certificate", harness.serverPeerCertChainLength > 0);
        assertEquals("the chain the server received is not the one the client sent",
            harness.clientLocalCertChainLength, harness.serverPeerCertChainLength);

        assertTrue("the server did not verify the client's Finished over the same transcript",
            Arrays.areEqual(harness.clientLocalVerifyData, harness.serverPeerVerifyData));
        assertTrue("the client did not verify the server's Finished over the same transcript",
            Arrays.areEqual(harness.serverLocalVerifyData, harness.clientPeerVerifyData));

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));

        /*
         * The client's Certificate and CertificateVerify are all at epoch 2, so its flight does not straddle
         * an epoch change: the progression is unchanged by client authentication.
         */
        checkEpochProgression(harness.clientRecords(), "client");
        checkEpochProgression(harness.serverRecords(), "server");
    }

    /**
     * RFC 8446 4.4.2. "If the client does not send any certificates (i.e., it sends an empty Certificate
     * message), the server MAY at its discretion either continue the handshake without client authentication".
     * The client still answers the CertificateRequest - with an empty certificate list and no CertificateVerify
     * - and the server, which only asked optionally, completes.
     */
    public void testClientServerWithClientAuthenticationDeclined() throws Exception
    {
        Harness harness = new Harness();
        harness.clientAuth = TlsTestConfig.CLIENT_AUTH_NONE;
        harness.serverCertReq = TlsTestConfig.SERVER_CERT_REQ_OPTIONAL;

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        /*
         * The server saw a Certificate message, and it was empty: a declining client is distinguished from an
         * authenticating one by the length of the chain in it, not by the message's absence.
         */
        assertEquals("the server did not see an empty client certificate", 0, harness.serverPeerCertChainLength);
        assertEquals("the client claimed a certificate it did not have", 0, harness.clientLocalCertChainLength);

        assertTrue("the server did not verify the client's Finished over the same transcript",
            Arrays.areEqual(harness.clientLocalVerifyData, harness.serverPeerVerifyData));

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));
    }

    /**
     * RFC 8446 4.4.2.4. "if the client's certificate chain is empty ... the server MAY ... abort the handshake
     * with a 'certificate_required' alert". A server that requires client authentication must reject a client
     * that declines, rather than silently treating the handshake as authenticated.
     */
    public void testClientServerWithMandatoryClientAuthenticationDeclined() throws Exception
    {
        Harness harness = new Harness();
        harness.clientAuth = TlsTestConfig.CLIENT_AUTH_NONE;
        harness.serverCertReq = TlsTestConfig.SERVER_CERT_REQ_MANDATORY;

        try
        {
            harness.run(16);

            fail("expected the server to abort when client authentication was declined");
        }
        catch (TlsFatalAlertReceived fatalAlert)
        {
            assertEquals("alert for a declined mandatory CertificateRequest", AlertDescription.certificate_required,
                fatalAlert.getAlertDescription());
        }

        assertEquals("the server did not see an empty client certificate", 0, harness.serverPeerCertChainLength);
    }

    /**
     * RFC 8446 4.4.3. The server really does verify the client's CertificateVerify signature: one bit of it is
     * flipped, which must be a fatal "decrypt_error". Without this, a CertificateVerify computed over the wrong
     * transcript - or over nothing at all - would pass {@link #testClientServerWithClientAuthentication}.
     */
    public void testClientServerWithACorruptedClientCertificateVerify() throws Exception
    {
        Harness harness = new Harness();
        harness.clientAuth = TlsTestConfig.CLIENT_AUTH_INVALID_VERIFY;
        harness.serverCertReq = TlsTestConfig.SERVER_CERT_REQ_MANDATORY;

        try
        {
            harness.run(16);

            fail("expected the server to reject a corrupted CertificateVerify");
        }
        catch (TlsFatalAlertReceived fatalAlert)
        {
            assertEquals("alert for a bad client CertificateVerify signature", AlertDescription.decrypt_error,
                fatalAlert.getAlertDescription());
        }

        assertTrue("the server did not receive a client certificate", harness.serverPeerCertChainLength > 0);
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

        String clientEpochs = epochSequence(harness.clientRecords());

        /*
         * The flight is a Certificate and a Finished, so two epoch-2 records, and both of them must come back:
         * counting epoch-2 records from the first epoch-3 record onwards is what distinguishes a
         * retransmission from the original flight, which is already two epoch-2 records of its own.
         */
        assertTrue("the client did not retransmit its whole final flight after reaching the application epoch"
            + " (epochs: " + clientEpochs + ")", countEpoch2AfterFirstEpoch3(clientEpochs) >= 2);

        checkUnifiedHeadersAfterHello(harness.clientRecords(), "client");

        /*
         * The final flight still goes out at the handshake epoch first, and the retransmission of it arrives
         * after the client has moved on to epoch 3 - which is the whole point: the write epoch is not wound
         * back, so the retransmission is addressed to the retained handshake epoch while application data
         * continues at the application epoch.
         */
        assertEquals("the client's first protected record was not at the handshake epoch", 2,
            firstProtectedEpoch(harness.clientRecords()));

        assertTrue("the client did not retransmit at the handshake epoch after reaching epoch 3 (epochs: "
            + clientEpochs + ")", lastProtectedEpoch(harness.clientRecords()) == 3
                && retransmittedAtHandshakeEpochAfterApplicationEpoch(clientEpochs));
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
     * The authenticated client flight, fragmented across several records and then lost. It is the largest
     * flight either peer sends - a real certificate chain plus a CertificateVerify over it - so it is the
     * only one the record layer has to fragment, and the per-fragment epoch bookkeeping and the flight
     * boundaries both have more to get wrong here than for a bare Finished.
     * <p>
     * The loss is deterministic rather than seeded-random: the datagram carrying the start of the flight is
     * dropped outright, the way {@link #testClientServerWithClientFinishedLost} drops the bare Finished, so
     * that the flight under test is certainly the thing that was lost and the drop is counted where the
     * test can see it. The same handshake is also run first at the normal MTU, purely to count how many
     * records the flight needs when nothing has to be fragmented: the two runs send the identical sequence
     * of handshake messages, so the extra records at the smaller MTU can only be fragmentation - which is
     * how fragmentation is established here without decrypting anything.
     * </p>
     */
    public void testClientServerWithClientAuthenticationFlightLost() throws Exception
    {
        Harness unfragmented = new Harness();
        unfragmented.clientAuth = TlsTestConfig.CLIENT_AUTH_VALID;
        unfragmented.serverCertReq = TlsTestConfig.SERVER_CERT_REQ_MANDATORY;

        unfragmented.run(16);

        assertNotNull("no application data echoed back", unfragmented.echo);

        String unfragmentedEpochs = epochSequence(unfragmented.clientRecords());
        int unfragmentedFlightRecords = countEpoch2BeforeFirstEpoch3(unfragmentedEpochs);

        assertTrue("the authenticated flight was not sent at the handshake epoch (epochs: "
            + unfragmentedEpochs + ")", unfragmentedFlightRecords > 0);

        Harness harness = new Harness();
        harness.clientAuth = TlsTestConfig.CLIENT_AUTH_VALID;
        harness.serverCertReq = TlsTestConfig.SERVER_CERT_REQ_MANDATORY;
        harness.networkMtu = FRAGMENTING_MTU;
        harness.dropFirstClientEpoch2Datagram = true;

        harness.run(16);

        // The drop really fired, so nothing below can pass on a path that turned out to be lossless
        assertTrue("the client's authenticated flight was not dropped", harness.dropped > 0);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        assertTrue("the client did not send a certificate of its own", harness.clientLocalCertChainLength > 0);
        assertEquals("the chain the server received is not the one the client sent",
            harness.clientLocalCertChainLength, harness.serverPeerCertChainLength);

        /*
         * The transcripts agreed all the way through the client's Certificate and CertificateVerify despite
         * the loss: a flight reassembled wrongly, or digested at the wrong boundary, would fail here.
         */
        assertTrue("the server did not verify the client's Finished over the same transcript",
            Arrays.areEqual(harness.clientLocalVerifyData, harness.serverPeerVerifyData));
        assertTrue("the client did not verify the server's Finished over the same transcript",
            Arrays.areEqual(harness.serverLocalVerifyData, harness.clientPeerVerifyData));

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));

        String clientEpochs = epochSequence(harness.clientRecords());
        int flightRecords = countEpoch2BeforeFirstEpoch3(clientEpochs);

        /*
         * RFC 9147 5.5. The same messages took more records at the smaller MTU, so at least one of them was
         * fragmented - and the flight therefore spans several records, with a fragment_offset to get right
         * on each of them, which is the specific risk this test exists for.
         */
        assertTrue("the reduced MTU did not fragment the authenticated flight (" + flightRecords
            + " records at MTU " + FRAGMENTING_MTU + " against " + unfragmentedFlightRecords + " at MTU "
            + DEFAULT_MTU + ")", flightRecords > unfragmentedFlightRecords);

        /*
         * And the whole of that fragmented flight came back after the client had moved on to the application
         * epoch: retransmission is at the epoch a fragment was first sent under, not at the current one.
         */
        assertTrue("the client did not retransmit its whole authenticated flight after reaching the"
            + " application epoch (epochs: " + clientEpochs + ")",
            countEpoch2AfterFirstEpoch3(clientEpochs) >= flightRecords);

        checkUnifiedHeadersAfterHello(harness.clientRecords(), "client");

        assertEquals("the client's first protected record was not at the handshake epoch", 2,
            firstProtectedEpoch(harness.clientRecords()));
        assertEquals("the client did not end at the application epoch", 3,
            lastProtectedEpoch(harness.clientRecords()));

        /*
         * The server never winds its own write epoch back: it has not seen the client's Finished when it
         * retransmits, so its whole run is monotonic even though the client's is not.
         */
        checkEpochProgression(harness.serverRecords(), "server");
    }

    /**
     * RFC 8446 4.4.1. A HelloRetryRequest changes how the transcript is computed: the first ClientHello is
     * replaced by a synthetic "message_hash" message. The handshake must complete after the retry, and the
     * proof that it did so over the right transcript is the Finished verification: if either peer computed that
     * substitution differently the verify_data would not match and the handshake would have failed with
     * "decrypt_error". The verify data of each side is compared against what the other side computed for it, so a transcript
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
     * RFC 9147 5.1. DTLS 1.3 replaces the HelloVerifyRequest with a HelloRetryRequest cookie and has no
     * HelloVerifyRequest at all, so a client that offered nothing earlier than DTLS 1.3 must refuse one. The
     * DTLS 1.2 countermeasure front end is put in front of the server here precisely because it is the thing
     * that would otherwise send one.
     */
    public void testHelloVerifyRequestRefusedWhenOnlyDTLSv13Offered() throws Exception
    {
        Harness harness = new Harness();
        harness.helloVerifyRequestFrontEnd = true;
        harness.serverHandshakeTimeoutMillis = 4000;

        try
        {
            harness.run(16);

            fail("expected the client to refuse a HelloVerifyRequest");
        }
        catch (TlsFatalAlert fatalAlert)
        {
            assertEquals("alert for a HelloVerifyRequest with only DTLS 1.3 offered",
                AlertDescription.unexpected_message, fatalAlert.getAlertDescription());
        }
    }

    /**
     * RFC 9147 5.1. The other half of the same rule, and the one a version-straddling client reaches: a client
     * that also offers DTLS 1.2 must accept a HelloVerifyRequest, since the server may be a 1.2 server - but
     * having answered one it must not then let the server select DTLS 1.3, because that handshake would have
     * been reached through a countermeasure DTLS 1.3 does not have. Without this check the cookie exchange is
     * a way in to a 1.3 handshake.
     */
    public void testDTLSv13RefusedAfterAHelloVerifyRequest() throws Exception
    {
        Harness harness = new Harness();
        harness.helloVerifyRequestFrontEnd = true;
        harness.clientVersions = ProtocolVersion.DTLSv13.downTo(ProtocolVersion.DTLSv12);
        harness.serverHandshakeTimeoutMillis = 4000;

        try
        {
            harness.run(16);

            fail("expected the client to refuse DTLS 1.3 after a HelloVerifyRequest");
        }
        catch (TlsFatalAlert fatalAlert)
        {
            assertEquals("alert for DTLS 1.3 selected after a HelloVerifyRequest",
                AlertDescription.illegal_parameter, fatalAlert.getAlertDescription());
        }
    }

    /**
     * The counterpart of the two above: the HelloVerifyRequest path that DTLS 1.2 depends on is untouched. A
     * client and server that both also speak DTLS 1.2 complete a 1.2 handshake through the cookie exchange,
     * exactly as the DTLS 1.2 suites do.
     */
    public void testHelloVerifyRequestStillWorksForDTLSv12() throws Exception
    {
        Harness harness = new Harness();
        harness.helloVerifyRequestFrontEnd = true;
        harness.clientVersions = ProtocolVersion.DTLSv13.downTo(ProtocolVersion.DTLSv12);
        harness.serverVersions = ProtocolVersion.DTLSv12.only();

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv12, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv12, harness.serverVersion);

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));
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

    /**
     * RFC 5705, and RFC 8446 7.5 for the DTLS 1.3 schedule. The exporter is what DTLS-SRTP and every other
     * RFC 5705 consumer is built on, so the properties asserted here are the ones those consumers rely on:
     * both peers derive the same material, the label separates one consumer's material from another's, and -
     * the part that could only be true of a DTLS 1.3 handshake - a null context and a zero-length context
     * produce the same material, because RFC 8446 7.5 has no way to tell them apart, where RFC 5705 4's
     * seed does and the DTLS 1.2 run below proves it does.
     * <p>
     * That last pair is what makes this more than "two handshakes produced different bytes", which two
     * handshakes with different randoms would satisfy however they derived them: it is a behavioural
     * difference between the two exporter paths, observed through the public API, in the direction each
     * specification requires.
     * </p>
     */
    public void testExportKeyingMaterial() throws Exception
    {
        Harness dtls13 = new Harness();

        dtls13.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, dtls13.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, dtls13.serverVersion);

        assertNotNull("no application data echoed back", dtls13.echo);

        /*
         * RFC 8446 Appendix D. A (D)TLS 1.3 peer reports extended_master_secret, which is what RFC 7627 5.4
         * makes the exporter conditional on - so the exporter is available at all over DTLS 1.3.
         */
        assertTrue("the client did not report extended_master_secret", dtls13.clientExtendedMasterSecret);
        assertTrue("the server did not report extended_master_secret", dtls13.serverExtendedMasterSecret);

        assertNotNull("the client exported no keying material", dtls13.clientKeyingMaterial);
        assertEquals("exported keying material length", EXPORTER_LENGTH, dtls13.clientKeyingMaterial.length);
        assertFalse("the client exported all-zero keying material", isAllZeroes(dtls13.clientKeyingMaterial));

        assertTrue("the peers exported different keying material",
            Arrays.areEqual(dtls13.clientKeyingMaterial, dtls13.serverKeyingMaterial));
        assertTrue("the peers exported different keying material for the second label",
            Arrays.areEqual(dtls13.clientKeyingMaterialOtherLabel, dtls13.serverKeyingMaterialOtherLabel));

        assertFalse("the exported keying material did not depend on the label",
            Arrays.areEqual(dtls13.clientKeyingMaterial, dtls13.clientKeyingMaterialOtherLabel));

        // RFC 8446 7.5. A zero-length context and no context at all are the same input to a 1.3 exporter
        assertTrue("an empty context changed the material a DTLS 1.3 handshake exported",
            Arrays.areEqual(dtls13.clientKeyingMaterial, dtls13.clientKeyingMaterialEmptyContext));
        assertTrue("the peers disagreed on the material for an empty context",
            Arrays.areEqual(dtls13.clientKeyingMaterialEmptyContext, dtls13.serverKeyingMaterialEmptyContext));

        Harness dtls12 = new Harness();
        dtls12.clientVersions = ProtocolVersion.DTLSv12.only();
        dtls12.serverVersions = ProtocolVersion.DTLSv12.only();

        dtls12.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv12, dtls12.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv12, dtls12.serverVersion);

        assertTrue("the DTLS 1.2 client did not report extended_master_secret",
            dtls12.clientExtendedMasterSecret);
        assertTrue("the DTLS 1.2 peers exported different keying material",
            Arrays.areEqual(dtls12.clientKeyingMaterial, dtls12.serverKeyingMaterial));

        assertFalse("the DTLS 1.2 and DTLS 1.3 handshakes exported the same keying material",
            Arrays.areEqual(dtls13.clientKeyingMaterial, dtls12.clientKeyingMaterial));

        /*
         * RFC 5705 4. The DTLS 1.2 seed is "client_random + server_random" with no context, and
         * "client_random + server_random + length + context" with one, so an empty context is not the same
         * input as none - the opposite of RFC 8446 7.5 above, which is how each assertion earns the other.
         */
        assertFalse("an empty context did not change the material a DTLS 1.2 handshake exported",
            Arrays.areEqual(dtls12.clientKeyingMaterial, dtls12.clientKeyingMaterialEmptyContext));
    }

    /**
     * RFC 5764, the reason this whole series exists: SRTP keying material out of a DTLS 1.3 handshake. The
     * client offers "use_srtp" with two protection profiles and an MKI, the server selects one of them, and
     * both peers derive the SRTP master keys and salts from the RFC 5705 exporter under
     * "EXTRACTOR-dtls_srtp".
     * <p>
     * The profile the server selects is the client's <em>second</em> preference, so the client could not
     * report the negotiated profile without having read the server's answer. Over DTLS 1.3 that answer cannot
     * be in the ServerHello - RFC 8446 4.2 permits "use_srtp" only in the ClientHello and EncryptedExtensions
     * - and the ServerHello on the wire is checked here to confirm it is not, which makes the client's
     * knowledge of the profile proof that the encrypted answer arrived and was processed.
     * </p>
     */
    public void testClientServerWithUseSRTP() throws Exception
    {
        Harness harness = new Harness();
        harness.useSrtp = true;

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));

        int expectedProfile = SRTP_PROTECTION_PROFILES[SRTP_PROTECTION_PROFILES.length - 1];

        assertEquals("the server did not select the expected SRTP protection profile", expectedProfile,
            harness.serverSrtpProtectionProfile);
        assertEquals("the client did not see the profile the server selected", expectedProfile,
            harness.clientSrtpProtectionProfile);

        assertTrue("the server did not echo the client's SRTP MKI",
            Arrays.areEqual(SRTP_MKI, harness.serverSrtpMki));
        assertTrue("the client did not receive its own SRTP MKI back",
            Arrays.areEqual(SRTP_MKI, harness.clientSrtpMki));

        assertNotNull("the client derived no SRTP keying material", harness.clientSrtpKeyingMaterial);
        assertEquals("SRTP keying material length", SRTP_KEYING_MATERIAL_LENGTH,
            harness.clientSrtpKeyingMaterial.length);
        assertFalse("the client derived all-zero SRTP keying material",
            isAllZeroes(harness.clientSrtpKeyingMaterial));

        assertTrue("the peers derived different SRTP keying material",
            Arrays.areEqual(harness.clientSrtpKeyingMaterial, harness.serverSrtpKeyingMaterial));

        /*
         * The SRTP material is the exporter's output for the RFC 5764 4.2 label, and nothing else: a peer
         * which returned the same bytes for every label would pass the agreement check above on its own.
         */
        assertFalse("the SRTP keying material was not label-specific",
            Arrays.areEqual(Arrays.copyOfRange(harness.clientSrtpKeyingMaterial, 0, EXPORTER_LENGTH),
                harness.clientKeyingMaterial));

        Vector clientHellos = handshakeBodies(harness.clientRecords(), HandshakeType.client_hello);
        Vector serverHellos = handshakeBodies(harness.serverRecords(), HandshakeType.server_hello);

        assertEquals("number of ClientHellos sent", 1, clientHellos.size());
        assertEquals("number of ServerHellos received", 1, serverHellos.size());

        assertNotNull("the ClientHello carried no use_srtp extension",
            clientHelloExtensionData((byte[])clientHellos.elementAt(0), ExtensionType.use_srtp));
        assertNull("the ServerHello carried a use_srtp extension, which RFC 8446 4.2 does not permit",
            serverHelloExtensionData((byte[])serverHellos.elementAt(0), ExtensionType.use_srtp));

        /*
         * And that null means the extension was absent rather than that the walk over the ServerHello's
         * extensions found nothing at all: "supported_versions" is certainly there, and is found.
         */
        assertNotNull("the ServerHello extensions could not be read",
            serverHelloExtensionData((byte[])serverHellos.elementAt(0), ExtensionType.supported_versions));

        checkUnifiedHeadersAfterHello(harness.clientRecords(), "client");
        checkEpochProgression(harness.clientRecords(), "client");
        checkEpochProgression(harness.serverRecords(), "server");
    }

    /**
     * A 1.3-capable client negotiates DTLS 1.2 with a 1.2-only server and completes. The failure this guards
     * against is state crossing between the two code paths - the defect Pion reported of its own fallback -
     * so it is not enough that the handshake completed: every record on the wire must be a legacy
     * DTLSPlaintext or DTLSCiphertext at epoch 0 or 1, there must be a change_cipher_spec, which DTLS 1.3 has
     * none of, and the exporter must behave as RFC 5705 4 says rather than as RFC 8446 7.5 does.
     */
    public void testFallbackToDTLSv12AgainstADTLSv12OnlyServer() throws Exception
    {
        Harness harness = new Harness();
        harness.clientVersions = ProtocolVersion.DTLSv13.downTo(ProtocolVersion.DTLSv12);
        harness.serverVersions = ProtocolVersion.DTLSv12.only();

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv12, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv12, harness.serverVersion);

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));

        assertEquals("cipher suites differ", harness.clientCipherSuite, harness.serverCipherSuite);
        assertFalse("a TLS 1.3 cipher suite was negotiated for a DTLS 1.2 handshake: "
            + harness.clientCipherSuite, isTLSv13CipherSuite(harness.clientCipherSuite));

        // The client really did offer DTLS 1.3, so the server really did have to decline it
        checkClientHelloOfferedDTLSv13(harness.clientRecords());

        checkLegacyRecordsThroughout(harness.clientRecords(), "client");
        checkLegacyRecordsThroughout(harness.serverRecords(), "server");

        checkDTLSv12Exporter(harness);
    }

    /**
     * The other direction of the fallback: a 1.2-only client against a 1.3-capable server. The server is the
     * side that chooses the version here, and having chosen 1.2 it must run the 1.2 path throughout.
     */
    public void testFallbackToDTLSv12AgainstADTLSv12OnlyClient() throws Exception
    {
        Harness harness = new Harness();
        harness.clientVersions = ProtocolVersion.DTLSv12.only();
        harness.serverVersions = ProtocolVersion.DTLSv13.downTo(ProtocolVersion.DTLSv12);

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv12, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv12, harness.serverVersion);

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));

        assertEquals("cipher suites differ", harness.clientCipherSuite, harness.serverCipherSuite);
        assertFalse("a TLS 1.3 cipher suite was negotiated for a DTLS 1.2 handshake: "
            + harness.clientCipherSuite, isTLSv13CipherSuite(harness.clientCipherSuite));

        checkLegacyRecordsThroughout(harness.clientRecords(), "client");
        checkLegacyRecordsThroughout(harness.serverRecords(), "server");

        checkDTLSv12Exporter(harness);
    }

    /**
     * RFC 8446 4.2.1. The first ClientHello offered DTLS 1.3 as its most preferred version, so a server that
     * negotiated DTLS 1.2 did so by declining 1.3 rather than by never being offered it.
     */
    private void checkClientHelloOfferedDTLSv13(Vector records)
    {
        Vector clientHellos = handshakeBodies(records, HandshakeType.client_hello);
        assertFalse("no ClientHello captured", clientHellos.isEmpty());

        byte[] supportedVersions = clientHelloExtensionData((byte[])clientHellos.elementAt(0),
            ExtensionType.supported_versions);

        assertNotNull("the ClientHello carried no supported_versions extension", supportedVersions);
        assertTrue("the supported_versions extension was too short", supportedVersions.length >= 3);

        // ProtocolVersion versions<2..254>, most preferred first
        assertEquals("supported_versions list length", supportedVersions.length - 1,
            supportedVersions[0] & 0xFF);
        assertEquals("the most preferred offered version was not DTLS 1.3", ProtocolVersion.DTLSv13,
            ProtocolVersion.get(supportedVersions[1] & 0xFF, supportedVersions[2] & 0xFF));
    }

    /**
     * RFC 5705 4. The handshake used the DTLS 1.2 exporter: both peers agree on the material, and a
     * zero-length context gives different material from no context at all, which the RFC 8446 7.5 exporter
     * of {@link #testExportKeyingMaterial} cannot do. A fallback handshake that had reached the 1.3 key
     * schedule would fail here even if everything on the wire looked legacy.
     */
    private void checkDTLSv12Exporter(Harness harness)
    {
        assertTrue("the client did not report extended_master_secret", harness.clientExtendedMasterSecret);
        assertTrue("the server did not report extended_master_secret", harness.serverExtendedMasterSecret);

        assertNotNull("the client exported no keying material", harness.clientKeyingMaterial);
        assertTrue("the peers exported different keying material",
            Arrays.areEqual(harness.clientKeyingMaterial, harness.serverKeyingMaterial));

        assertFalse("an empty context did not change the material a DTLS 1.2 handshake exported",
            Arrays.areEqual(harness.clientKeyingMaterial, harness.clientKeyingMaterialEmptyContext));
    }

    /**
     * RFC 6347 4.1 and RFC 9147 4. Every record a side sent was a legacy DTLS 1.2 record - never the DTLS 1.3
     * unified header - at epoch 0 or 1 and with a legacy_record_version of 0xfeff or 0xfefd, the side reached
     * epoch 1, and a change_cipher_spec is among the records, which is what a DTLS 1.3 handshake would never
     * produce (RFC 9147 5).
     */
    private void checkLegacyRecordsThroughout(Vector records, String side)
    {
        assertFalse("no " + side + " records captured", records.isEmpty());

        int epoch1Records = 0;
        boolean seenChangeCipherSpec = false;

        for (int i = 0; i < records.size(); ++i)
        {
            Record record = (Record)records.elementAt(i);

            assertFalse(side + " record " + i + " used the DTLS 1.3 unified header (first byte 0x"
                + Integer.toHexString(record.getFirstByte()) + ")", record.isUnified());

            ProtocolVersion version = record.getPlaintextVersion();
            assertTrue(side + " record " + i + " legacy_record_version " + version,
                ProtocolVersion.DTLSv10 == version || ProtocolVersion.DTLSv12 == version);

            int epoch = record.getPlaintextEpoch();
            assertTrue(side + " record " + i + " was at epoch " + epoch, 0 == epoch || 1 == epoch);

            if (1 == epoch)
            {
                ++epoch1Records;
            }

            if (ContentType.change_cipher_spec == record.getContentType())
            {
                assertEquals(side + " sent a change_cipher_spec at epoch " + epoch, 0, epoch);
                seenChangeCipherSpec = true;
            }
        }

        assertTrue("the " + side + " never reached the DTLS 1.2 epoch 1", epoch1Records > 0);
        assertTrue("the " + side + " sent no change_cipher_spec", seenChangeCipherSpec);
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
        int extensionDataOff = clientHelloExtensionDataOffset(buf, bodyOff, ExtensionType.cookie);

        // The extension data is opaque cookie<1..2^16-1>, so skip its own length prefix
        return extensionDataOff < 0 ? -1 : extensionDataOff + 2;
    }

    /** The extension_data of the given ClientHello extension (RFC 8446 4.2), or null if it has none. */
    private static byte[] clientHelloExtensionData(byte[] body, int extensionType)
    {
        int off = clientHelloExtensionDataOffset(body, 0, extensionType);

        return off < 0 ? null : Arrays.copyOfRange(body, off, off + readUint16(body, off - 2));
    }

    /**
     * The offset within 'buf' of the extension_data of the given extension of the ClientHello whose body
     * begins at 'bodyOff', or -1 if it has no such extension. Its length is the uint16 two bytes earlier.
     */
    private static int clientHelloExtensionDataOffset(byte[] buf, int bodyOff, int extensionType)
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
            int extensionLength = readUint16(buf, pos + 2);

            if (extensionType == readUint16(buf, pos))
            {
                return pos + 4;
            }

            pos += 4 + extensionLength;
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
        byte[] extensionData = serverHelloExtensionData(body, ExtensionType.cookie);

        // The extension data is opaque cookie<1..2^16-1>, so skip its own length prefix
        return null == extensionData ? null : Arrays.copyOfRange(extensionData, 2, extensionData.length);
    }

    /** The extension_data of the given ServerHello extension (RFC 8446 4.2), or null if it has none. */
    private static byte[] serverHelloExtensionData(byte[] body, int extensionType)
    {
        int pos = 2 + 32;
        // legacy_session_id_echo
        pos += 1 + (body[pos] & 0xFF);
        // cipher_suite and legacy_compression_method
        pos += 3;

        return findExtensionData(body, pos, extensionType);
    }

    /**
     * Walks the extensions block beginning at 'pos' (a uint16 length followed by type/length/data triples) and
     * returns the extension_data of the extension of the given type, or null if there is none.
     */
    private static byte[] findExtensionData(byte[] body, int pos, int extensionType)
    {
        if (pos + 2 > body.length)
        {
            return null;
        }

        int end = pos + 2 + readUint16(body, pos);
        pos += 2;

        while (pos + 4 <= end)
        {
            int extensionLength = readUint16(body, pos + 2);

            if (extensionType == readUint16(body, pos))
            {
                return Arrays.copyOfRange(body, pos + 4, pos + 4 + extensionLength);
            }

            pos += 4 + extensionLength;
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

    /**
     * Whether a side, having reached the application epoch, then sent something at the handshake epoch and
     * carried on at the application epoch: a '3' in the epoch sequence, then a '2', then another '3'. The
     * flight being retransmitted may be any number of records, so the run of 2s is not a fixed length.
     */
    private static boolean retransmittedAtHandshakeEpochAfterApplicationEpoch(String epochs)
    {
        int epoch3 = epochs.indexOf('3');
        int epoch2After = epoch3 < 0 ? -1 : epochs.indexOf('2', epoch3 + 1);

        return epoch2After >= 0 && epochs.indexOf('3', epoch2After + 1) >= 0;
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

    /**
     * How many epoch-2 records appear after the first epoch-3 one. A side's original final flight is already
     * several epoch-2 records, so only the ones after it has moved on to the application epoch can be a
     * retransmission of that flight, and the count says how much of the flight came back.
     */
    private static int countEpoch2AfterFirstEpoch3(String epochs)
    {
        int epoch3 = epochs.indexOf('3');
        if (epoch3 < 0)
        {
            return 0;
        }

        int count = 0;
        for (int i = epoch3 + 1; i < epochs.length(); ++i)
        {
            if ('2' == epochs.charAt(i))
            {
                ++count;
            }
        }

        return count;
    }

    /**
     * How many epoch-2 records a side sent before the first epoch-3 one: the size, in records, of its
     * original final flight.
     */
    private static int countEpoch2BeforeFirstEpoch3(String epochs)
    {
        int epoch3 = epochs.indexOf('3');
        int end = epoch3 < 0 ? epochs.length() : epoch3;

        int count = 0;
        for (int i = 0; i < end; ++i)
        {
            if ('2' == epochs.charAt(i))
            {
                ++count;
            }
        }

        return count;
    }

    private static boolean isAllZeroes(byte[] bs)
    {
        for (int i = 0; i < bs.length; ++i)
        {
            if (0 != bs[i])
            {
                return false;
            }
        }

        return true;
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
        boolean helloVerifyRequestFrontEnd = false;
        ProtocolVersion[] clientVersions = ProtocolVersion.DTLSv13.only();
        ProtocolVersion[] serverVersions = ProtocolVersion.DTLSv13.only();

        /*
         * Client authentication, configured as TlsTestConfig / DTLSTestSuite configure it for DTLS 1.2: what
         * the server asks for, and what the client answers with. The defaults are what MockDTLSServer and
         * MockDTLSClient do of their own accord, which is to ask optionally and decline - the same pair of
         * defaults MockTlsServer and MockTlsClient have for TLS 1.3.
         */
        int clientAuth = TlsTestConfig.CLIENT_AUTH_NONE;
        int serverCertReq = TlsTestConfig.SERVER_CERT_REQ_OPTIONAL;

        /*
         * RFC 5764 4.1. Whether the client offers the "use_srtp" extension, which this server then answers
         * with one of the profiles offered.
         */
        boolean useSrtp = false;

        /*
         * Only worth lowering for a test where the client aborts partway: the server then has no peer left to
         * hear from, and shutting the harness down waits for its handshake to give up. Where the client aborts
         * before installing the handshake traffic keys, its alert is an epoch-0 record the server can no
         * longer read, so giving up is the only way out.
         */
        int serverHandshakeTimeoutMillis = HANDSHAKE_TIMEOUT_MILLIS;
        int networkMtu = DEFAULT_MTU;
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

        // Lengths of the certificate chain the client sent and the one the server received, or -1 for none
        int clientLocalCertChainLength = -1;
        int serverPeerCertChainLength = -1;

        // How many CertificateRequests the client was asked to answer
        int clientCertificateRequestsSeen = 0;

        /*
         * RFC 5705 exporter output, taken on both peers for the same label, context and length. The
         * 'EmptyContext' pair uses a zero-length context where the first pair passes none at all, which RFC
         * 8446 7.5 treats as the same input and RFC 5705 4 does not.
         */
        boolean clientExtendedMasterSecret = false;
        boolean serverExtendedMasterSecret = false;
        byte[] clientKeyingMaterial = null;
        byte[] serverKeyingMaterial = null;
        byte[] clientKeyingMaterialEmptyContext = null;
        byte[] serverKeyingMaterialEmptyContext = null;
        byte[] clientKeyingMaterialOtherLabel = null;
        byte[] serverKeyingMaterialOtherLabel = null;

        // RFC 5764 4.1.1 and 4.2. The negotiated profile and MKI as each peer saw them, and the SRTP keys
        int clientSrtpProtectionProfile = -1;
        int serverSrtpProtectionProfile = -1;
        byte[] clientSrtpMki = null;
        byte[] serverSrtpMki = null;
        byte[] clientSrtpKeyingMaterial = null;
        byte[] serverSrtpKeyingMaterial = null;

        // The client's "use_srtp" offer as the server received it
        private UseSRTPData offeredSrtp = null;

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
                    return clientVersions;
                }

                public void notifyServerVersion(ProtocolVersion version) throws IOException
                {
                    super.notifyServerVersion(version);

                    clientVersion = version;
                }

                public TlsAuthentication getAuthentication() throws IOException
                {
                    final TlsAuthentication authentication = super.getAuthentication();

                    return new TlsAuthentication()
                    {
                        public void notifyServerCertificate(TlsServerCertificate serverCertificate)
                            throws IOException
                        {
                            authentication.notifyServerCertificate(serverCertificate);
                        }

                        /*
                         * MockDTLSClient's own answer depends on the 'certificate_types' a DTLS 1.3
                         * CertificateRequest does not have (RFC 8446 4.3.2 replaced them with
                         * 'signature_algorithms'), so the credentials are selected here instead, the way
                         * TlsTestClientImpl selects them for TLS 1.3.
                         */
                        public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                            throws IOException
                        {
                            ++clientCertificateRequestsSeen;

                            if (TlsTestConfig.CLIENT_AUTH_NONE == clientAuth)
                            {
                                return null;
                            }

                            return clientCredentials(certificateRequest);
                        }
                    };
                }

                /** RFC 5764 4.1.1. The client offers its protection profiles and an MKI in the ClientHello. */
                public Hashtable getClientExtensions() throws IOException
                {
                    Hashtable clientExtensions = super.getClientExtensions();

                    if (useSrtp)
                    {
                        clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(clientExtensions);

                        TlsSRTPUtils.addUseSRTPExtension(clientExtensions,
                            new UseSRTPData(SRTP_PROTECTION_PROFILES, SRTP_MKI));
                    }

                    return clientExtensions;
                }

                /**
                 * RFC 5764 4.1.1. "The server response is the ServerHello" for DTLS 1.2; over DTLS 1.3 the
                 * answer travels in EncryptedExtensions instead (RFC 8446 4.2 permits "use_srtp" only in the
                 * ClientHello and EncryptedExtensions). Either way it reaches the peer here.
                 */
                public void processServerExtensions(Hashtable serverExtensions) throws IOException
                {
                    super.processServerExtensions(serverExtensions);

                    UseSRTPData useSRTPData = TlsSRTPUtils.getUseSRTPExtension(serverExtensions);
                    if (null != useSRTPData)
                    {
                        int[] protectionProfiles = useSRTPData.getProtectionProfiles();
                        if (1 != protectionProfiles.length)
                        {
                            throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                                "the server chose " + protectionProfiles.length + " SRTP protection profiles");
                        }

                        clientSrtpProtectionProfile = protectionProfiles[0];
                        clientSrtpMki = useSRTPData.getMki();
                    }
                }

                public void notifyHandshakeComplete() throws IOException
                {
                    super.notifyHandshakeComplete();

                    SecurityParameters sp = context.getSecurityParametersConnection();

                    clientCipherSuite = sp.getCipherSuite();
                    clientLocalVerifyData = sp.getLocalVerifyData();
                    clientPeerVerifyData = sp.getPeerVerifyData();

                    Certificate localCertificate = sp.getLocalCertificate();
                    clientLocalCertChainLength = null == localCertificate
                        ?   -1
                        :   localCertificate.getCertificateList().length;

                    clientExtendedMasterSecret = sp.isExtendedMasterSecret();
                    if (clientExtendedMasterSecret)
                    {
                        clientKeyingMaterial = context.exportKeyingMaterial(EXPORTER_LABEL, null,
                            EXPORTER_LENGTH);
                        clientKeyingMaterialEmptyContext = context.exportKeyingMaterial(EXPORTER_LABEL,
                            new byte[0], EXPORTER_LENGTH);
                        clientKeyingMaterialOtherLabel = context.exportKeyingMaterial(EXPORTER_LABEL_OTHER,
                            null, EXPORTER_LENGTH);
                    }

                    if (clientSrtpProtectionProfile >= 0)
                    {
                        clientSrtpKeyingMaterial = context.exportKeyingMaterial(SRTP_EXPORTER_LABEL, null,
                            SRTP_KEYING_MATERIAL_LENGTH);
                    }
                }

                /**
                 * The RSA client credentials, with the CertificateVerify signature corrupted for
                 * CLIENT_AUTH_INVALID_VERIFY. RSA PKCS#1 v1.5 signatures are not usable in a (D)TLS 1.3
                 * CertificateVerify, so the PSS scheme is selected explicitly, as TlsTestClientImpl does.
                 */
                private TlsCredentials clientCredentials(CertificateRequest certificateRequest) throws IOException
                {
                    Vector supportedSigAlgs = certificateRequest.getSupportedSignatureAlgorithms();

                    SignatureAndHashAlgorithm pss = SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
                    if (!TlsUtils.containsSignatureAlgorithm(supportedSigAlgs, pss))
                    {
                        throw new TlsFatalAlert(AlertDescription.internal_error,
                            "the server did not offer " + pss);
                    }

                    final TlsCredentialedSigner credentials = TlsTestUtils.loadSignerCredentials(context,
                        new String[]{ "x509-client-rsa.pem" }, "x509-client-key-rsa.pem", pss);

                    if (TlsTestConfig.CLIENT_AUTH_INVALID_VERIFY != clientAuth)
                    {
                        return credentials;
                    }

                    return new TlsCredentialedSigner()
                    {
                        public byte[] generateRawSignature(byte[] hash) throws IOException
                        {
                            return corruptBit(credentials.generateRawSignature(hash));
                        }

                        public Certificate getCertificate()
                        {
                            return credentials.getCertificate();
                        }

                        public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
                        {
                            return credentials.getSignatureAndHashAlgorithm();
                        }

                        public TlsStreamSigner getStreamSigner() throws IOException
                        {
                            final TlsStreamSigner streamSigner = credentials.getStreamSigner();
                            if (null == streamSigner)
                            {
                                return null;
                            }

                            return new TlsStreamSigner()
                            {
                                public OutputStream getOutputStream() throws IOException
                                {
                                    return streamSigner.getOutputStream();
                                }

                                public byte[] getSignature() throws IOException
                                {
                                    return corruptBit(streamSigner.getSignature());
                                }
                            };
                        }
                    };
                }

                private byte[] corruptBit(byte[] bs)
                {
                    bs = Arrays.clone(bs);

                    int bit = context.getCrypto().getSecureRandom().nextInt(bs.length << 3);
                    bs[bit >>> 3] ^= (1 << (bit & 7));

                    return bs;
                }
            };
            client.setHandshakeTimeoutMillis(HANDSHAKE_TIMEOUT_MILLIS);

            MockDTLSServer server = new MockDTLSServer()
            {
                protected ProtocolVersion[] getSupportedVersions()
                {
                    return serverVersions;
                }

                public int getHandshakeTimeoutMillis()
                {
                    return serverHandshakeTimeoutMillis;
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

                public void processClientExtensions(Hashtable clientExtensions) throws IOException
                {
                    super.processClientExtensions(clientExtensions);

                    offeredSrtp = TlsSRTPUtils.getUseSRTPExtension(clientExtensions);
                }

                /**
                 * RFC 5764 4.1.1. "The server, if it selects a profile, MUST include a single chosen profile
                 * in its response" and, if the client offered an MKI, echoes it. The last of the offered
                 * profiles is chosen rather than the first, so the client cannot report the right profile by
                 * reporting its own preference.
                 */
                public Hashtable getServerExtensions() throws IOException
                {
                    Hashtable serverExtensions = super.getServerExtensions();

                    if (null != offeredSrtp)
                    {
                        serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(serverExtensions);

                        int[] offeredProfiles = offeredSrtp.getProtectionProfiles();
                        serverSrtpProtectionProfile = offeredProfiles[offeredProfiles.length - 1];
                        serverSrtpMki = offeredSrtp.getMki();

                        TlsSRTPUtils.addUseSRTPExtension(serverExtensions,
                            new UseSRTPData(new int[]{ serverSrtpProtectionProfile }, serverSrtpMki));
                    }

                    return serverExtensions;
                }

                public CertificateRequest getCertificateRequest() throws IOException
                {
                    if (TlsTestConfig.SERVER_CERT_REQ_NONE == serverCertReq)
                    {
                        return null;
                    }

                    return super.getCertificateRequest();
                }

                public void notifyClientCertificate(Certificate clientCertificate) throws IOException
                {
                    serverPeerCertChainLength = clientCertificate.getCertificateList().length;

                    /*
                     * RFC 8446 4.4.2.4. An empty chain is the client declining, which a server that requires
                     * client authentication must refuse - as TlsTestServerImpl refuses it for DTLS 1.2, with
                     * the 1.3 alert.
                     */
                    if (clientCertificate.isEmpty() && TlsTestConfig.SERVER_CERT_REQ_MANDATORY == serverCertReq)
                    {
                        throw new TlsFatalAlert(AlertDescription.certificate_required);
                    }

                    super.notifyClientCertificate(clientCertificate);
                }

                public void notifyHandshakeComplete() throws IOException
                {
                    super.notifyHandshakeComplete();

                    SecurityParameters sp = context.getSecurityParametersConnection();

                    serverCipherSuite = sp.getCipherSuite();
                    serverLocalVerifyData = sp.getLocalVerifyData();
                    serverPeerVerifyData = sp.getPeerVerifyData();

                    serverExtendedMasterSecret = sp.isExtendedMasterSecret();
                    if (serverExtendedMasterSecret)
                    {
                        serverKeyingMaterial = context.exportKeyingMaterial(EXPORTER_LABEL, null,
                            EXPORTER_LENGTH);
                        serverKeyingMaterialEmptyContext = context.exportKeyingMaterial(EXPORTER_LABEL,
                            new byte[0], EXPORTER_LENGTH);
                        serverKeyingMaterialOtherLabel = context.exportKeyingMaterial(EXPORTER_LABEL_OTHER,
                            null, EXPORTER_LENGTH);
                    }

                    if (serverSrtpProtectionProfile >= 0)
                    {
                        serverSrtpKeyingMaterial = context.exportKeyingMaterial(SRTP_EXPORTER_LABEL, null,
                            SRTP_KEYING_MATERIAL_LENGTH);
                    }
                }
            };

            MockDatagramAssociation network = new MockDatagramAssociation(networkMtu);

            DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

            ServerThread serverThread = new ServerThread(serverProtocol, server, network.getServer(),
                helloVerifyRequestFrontEnd);
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
            /*
             * The client's ClientHello is message_seq 0, its Certificate answering the server's
             * CertificateRequest is 1, and its Finished is 2.
             */
            record[off + 5] = (byte)2;
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
        private final boolean helloVerifyRequestFrontEnd;
        private volatile boolean isShutdown = false;

        ServerThread(DTLSServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport,
            boolean helloVerifyRequestFrontEnd)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
            this.serverTransport = serverTransport;
            this.helloVerifyRequestFrontEnd = helloVerifyRequestFrontEnd;
        }

        public void run()
        {
            try
            {
                /*
                 * NOTE: By default not the DTLSVerifier harness the DTLS 1.2 tests use: that issues a DTLS
                 * 1.2 HelloVerifyRequest, where RFC 9147 5.1 uses a HelloRetryRequest cookie instead. The
                 * tests of that rule turn it on deliberately, to check that a DTLS 1.3 handshake cannot be
                 * reached through it.
                 */
                DTLSRequest request = helloVerifyRequestFrontEnd ? verifyRequest() : null;

                DTLSTransport dtlsTransport = serverProtocol.accept(server, serverTransport, request);

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

        /**
         * The DTLS 1.2 denial-of-service countermeasure as a front end, exactly as DTLSProtocolTest drives
         * it: datagrams are read until one carries a ClientHello with a valid cookie, and anything else is
         * answered with a HelloVerifyRequest.
         */
        private DTLSRequest verifyRequest() throws IOException
        {
            TlsCrypto serverCrypto = server.getCrypto();

            DTLSVerifier verifier = new DTLSVerifier(serverCrypto);

            int receiveLimit = serverTransport.getReceiveLimit();
            byte[] buf = new byte[receiveLimit];

            for (;;)
            {
                if (isShutdown)
                {
                    return null;
                }

                int length = serverTransport.receive(buf, 0, receiveLimit, 100);
                if (length > 0)
                {
                    DTLSRequest request = verifier.verifyRequest(CLIENT_ID, buf, 0, length, serverTransport);
                    if (null != request)
                    {
                        return request;
                    }
                }
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
