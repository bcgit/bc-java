package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * RFC 9147 5.2: "In DTLS 1.3, the message transcript is computed over the original TLS 1.3-style Handshake
 * messages without the message_seq, fragment_offset, and fragment_length values."
 * <p>
 * These assert the transcript bytes directly, against an independently computed digest, because no
 * handshake between two Bouncy Castle peers can catch this: both would hash the same wrong bytes, agree
 * with each other, and fail only against some other implementation.
 * </p>
 */
public class DTLSTranscriptHashTest
    extends TestCase
{
    private static final int MESSAGE_SEQ = 7;

    private static final byte[] CLIENT_HELLO_BODY = body(0x10, 40);
    private static final byte[] SERVER_HELLO_BODY = body(0x20, 24);
    private static final byte[] CERTIFICATE_BODY = body(0x30, 11);

    /**
     * A DTLS 1.3 transcript hashes msg_type || uint24 length || body, and nothing else.
     */
    public void testDTLSv13TranscriptOmitsTheDTLSMessageHeader() throws Exception
    {
        byte[] transcript = digestOneMessage(ProtocolVersion.DTLSv13, HandshakeType.certificate,
            CERTIFICATE_BODY);

        assertTrue("DTLS 1.3 must hash the 4-byte TLS header form",
            Arrays.areEqual(sha256(tlsHeaderForm(HandshakeType.certificate, CERTIFICATE_BODY)), transcript));

        assertFalse("DTLS 1.3 must not hash the 12-byte DTLS header form",
            Arrays.areEqual(sha256(dtlsHeaderForm(HandshakeType.certificate, MESSAGE_SEQ, CERTIFICATE_BODY)),
                transcript));
    }

    /**
     * DTLS 1.2 is unchanged: the full 12-byte DTLS handshake header, message_seq included.
     */
    public void testDTLSv12TranscriptKeepsTheDTLSMessageHeader() throws Exception
    {
        byte[] transcript = digestOneMessage(ProtocolVersion.DTLSv12, HandshakeType.certificate,
            CERTIFICATE_BODY);

        assertTrue("DTLS 1.2 must hash the 12-byte DTLS header form",
            Arrays.areEqual(sha256(dtlsHeaderForm(HandshakeType.certificate, MESSAGE_SEQ, CERTIFICATE_BODY)),
                transcript));

        assertFalse("DTLS 1.2 must not hash the 4-byte TLS header form",
            Arrays.areEqual(sha256(tlsHeaderForm(HandshakeType.certificate, CERTIFICATE_BODY)), transcript));
    }

    /**
     * The two forms must actually differ, so that neither test above could pass by accident.
     */
    public void testTheTwoTranscriptFormsDiffer() throws Exception
    {
        byte[] dtls13 = digestOneMessage(ProtocolVersion.DTLSv13, HandshakeType.certificate, CERTIFICATE_BODY);
        byte[] dtls12 = digestOneMessage(ProtocolVersion.DTLSv12, HandshakeType.certificate, CERTIFICATE_BODY);

        assertFalse("the DTLS 1.2 and DTLS 1.3 transcripts must not coincide", Arrays.areEqual(dtls13, dtls12));
    }

    /**
     * The ordering case, and the reason the encoding cannot be chosen per message as it arrives: the
     * ClientHello is hashed before any version has been negotiated. Once DTLS 1.3 is selected, the
     * ClientHello must be in the transcript in the 4-byte form too, not just the messages that followed it.
     */
    public void testClientHelloHashedBeforeTheVersionIsKnownUsesTheDTLSv13Form() throws Exception
    {
        Fixture fixture = new Fixture(null);

        // the ClientHello: no version negotiated yet, exactly as in a real handshake
        fixture.digest(HandshakeType.client_hello, 0, CLIENT_HELLO_BODY);

        fixture.negotiate(ProtocolVersion.DTLSv13);

        fixture.digest(HandshakeType.server_hello, 0, SERVER_HELLO_BODY);

        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        expected.write(tlsHeaderForm(HandshakeType.client_hello, CLIENT_HELLO_BODY));
        expected.write(tlsHeaderForm(HandshakeType.server_hello, SERVER_HELLO_BODY));

        assertTrue("both messages must use the 4-byte form, the ClientHello included",
            Arrays.areEqual(sha256(expected.toByteArray()), fixture.transcript()));

        // the exact defect a naive version test would produce: ClientHello 12-byte, ServerHello 4-byte
        ByteArrayOutputStream mixed = new ByteArrayOutputStream();
        mixed.write(dtlsHeaderForm(HandshakeType.client_hello, 0, CLIENT_HELLO_BODY));
        mixed.write(tlsHeaderForm(HandshakeType.server_hello, SERVER_HELLO_BODY));

        assertFalse("the ClientHello must not be left in the 12-byte form",
            Arrays.areEqual(sha256(mixed.toByteArray()), fixture.transcript()));
    }

    /**
     * The same deferral must leave a DTLS 1.2 transcript byte-identical to what it has always been.
     */
    public void testClientHelloHashedBeforeTheVersionIsKnownUsesTheDTLSv12Form() throws Exception
    {
        Fixture fixture = new Fixture(null);

        fixture.digest(HandshakeType.client_hello, 0, CLIENT_HELLO_BODY);

        fixture.negotiate(ProtocolVersion.DTLSv12);

        fixture.digest(HandshakeType.server_hello, 0, SERVER_HELLO_BODY);

        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        expected.write(dtlsHeaderForm(HandshakeType.client_hello, 0, CLIENT_HELLO_BODY));
        expected.write(dtlsHeaderForm(HandshakeType.server_hello, 0, SERVER_HELLO_BODY));

        assertTrue("both messages must use the 12-byte form",
            Arrays.areEqual(sha256(expected.toByteArray()), fixture.transcript()));
    }

    /**
     * HelloVerifyRequest stays out of the transcript in every version.
     */
    public void testHelloVerifyRequestIsNotInTheTranscript() throws Exception
    {
        Fixture fixture = new Fixture(ProtocolVersion.DTLSv12);

        fixture.digest(HandshakeType.client_hello, 0, CLIENT_HELLO_BODY);
        fixture.digest(HandshakeType.hello_verify_request, 0, body(0x40, 6));
        fixture.digest(HandshakeType.server_hello, 1, SERVER_HELLO_BODY);

        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        expected.write(dtlsHeaderForm(HandshakeType.client_hello, 0, CLIENT_HELLO_BODY));
        expected.write(dtlsHeaderForm(HandshakeType.server_hello, 1, SERVER_HELLO_BODY));

        assertTrue("HelloVerifyRequest must not be hashed",
            Arrays.areEqual(sha256(expected.toByteArray()), fixture.transcript()));
    }

    private static byte[] digestOneMessage(ProtocolVersion negotiatedVersion, short msgType, byte[] msgBody)
        throws IOException
    {
        Fixture fixture = new Fixture(negotiatedVersion);

        fixture.digest(msgType, MESSAGE_SEQ, msgBody);

        return fixture.transcript();
    }

    /**
     * A real {@link DTLSReliableHandshake} over a real record layer, driven through the same
     * package-private digest entry point that {@link DTLSServerProtocol} uses for a delayed-digest
     * CertificateVerify. Nothing is sent or received, so the record layer is only what the constructor
     * needs.
     */
    private static class Fixture
    {
        private final BcTlsCrypto crypto = new BcTlsCrypto();
        private final AbstractTlsContext context;
        private final DTLSReliableHandshake handshake;

        Fixture(ProtocolVersion negotiatedVersion) throws IOException
        {
            byte[] secret = new byte[32];

            this.context = TlsAEADCipherDTLS13Test.createContext(crypto, false,
                CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, secret, secret);

            SecurityParameters securityParameters = context.getSecurityParametersHandshake();

            // NOTE: createContext pins DTLS 1.3; these tests choose, and may leave it not yet negotiated
            securityParameters.negotiatedVersion = negotiatedVersion;

            /*
             * Only selects SHA-256 as the transcript hash, which is what the independently computed
             * expected values use. Not itself under test.
             */
            securityParameters.prfAlgorithm = PRFAlgorithm.tls_prf_sha256;

            TlsPeer peer = new DefaultTlsClient(crypto)
            {
                public TlsAuthentication getAuthentication()
                {
                    return null;
                }
            };

            DTLSRecordLayer recordLayer = new DTLSRecordLayer(context, peer,
                new DTLSRecordLayerAggregationTest.CapturingTransport());

            this.handshake = new DTLSReliableHandshake(context, recordLayer, 60000, 1000, null, 1 << 14);
        }

        void negotiate(ProtocolVersion negotiatedVersion)
        {
            context.getSecurityParametersHandshake().negotiatedVersion = negotiatedVersion;
        }

        void digest(short msgType, int messageSeq, byte[] msgBody) throws IOException
        {
            handshake.updateHandshakeMessagesDigest(
                new DTLSReliableHandshake.Message(messageSeq, msgType, msgBody));
        }

        byte[] transcript() throws IOException
        {
            TlsHandshakeHash handshakeHash = handshake.getHandshakeHash();
            handshakeHash.notifyPRFDetermined();

            return TlsUtils.getCurrentPRFHash(handshakeHash);
        }
    }

    /** RFC 8446 4: msg_type || uint24 length || body. */
    private static byte[] tlsHeaderForm(short msgType, byte[] msgBody)
    {
        byte[] buf = new byte[4 + msgBody.length];
        TlsUtils.writeUint8(msgType, buf, 0);
        TlsUtils.writeUint24(msgBody.length, buf, 1);
        System.arraycopy(msgBody, 0, buf, 4, msgBody.length);
        return buf;
    }

    /** RFC 9147 5.2: the same, plus message_seq, fragment_offset and fragment_length. */
    private static byte[] dtlsHeaderForm(short msgType, int messageSeq, byte[] msgBody)
    {
        byte[] buf = new byte[12 + msgBody.length];
        TlsUtils.writeUint8(msgType, buf, 0);
        TlsUtils.writeUint24(msgBody.length, buf, 1);
        TlsUtils.writeUint16(messageSeq, buf, 4);
        TlsUtils.writeUint24(0, buf, 6);
        TlsUtils.writeUint24(msgBody.length, buf, 9);
        System.arraycopy(msgBody, 0, buf, 12, msgBody.length);
        return buf;
    }

    private static byte[] sha256(byte[] input)
    {
        TlsHash hash = new BcTlsCrypto().createHash(CryptoHashAlgorithm.sha256);
        hash.update(input, 0, input.length);
        return hash.calculateHash();
    }

    private static byte[] body(int first, int length)
    {
        byte[] buf = new byte[length];
        for (int i = 0; i < length; ++i)
        {
            buf[i] = (byte)(first + i);
        }
        return buf;
    }
}
