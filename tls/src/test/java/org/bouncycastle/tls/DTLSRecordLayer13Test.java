package org.bouncycastle.tls;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsDTLS13Cipher;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * DTLS 1.3 record layer (RFC 9147 4): protected records use the unified header, records round-trip between two
 * record layers, replays and short records are dropped, several records share a datagram, and the epoch switch
 * API drives epochs 2 and 3.
 */
public class DTLSRecordLayer13Test
    extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private DTLSRecordLayer13TestSupport support;
    private DTLSRecordLayer13TestSupport.Queue clientToServer, serverToClient;
    private DTLSRecordLayer13TestSupport.Side client, server;

    private void setUpPair(int cipherSuite, int hash) throws IOException
    {
        support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(cipherSuite, hash);
        clientToServer = support.clientToServer;
        serverToClient = support.serverToClient;
        client = support.client;
        server = support.server;
    }

    private static byte[] receive(DTLSRecordLayer13TestSupport.Side side, int waitMillis) throws IOException
    {
        return DTLSRecordLayer13TestSupport.receive(side, waitMillis);
    }

    public void testProtectedRecordUsesUnifiedHeader() throws Exception
    {
        setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        byte[] data = new byte[50];
        RANDOM.nextBytes(data);
        client.recordLayer.send(data, 0, data.length);

        byte[] datagram = clientToServer.peekLast();
        int firstByte = datagram[0] & 0xFF;
        assertTrue(DTLS13UnifiedHeader.isCiphertextRecord(firstByte));
        assertTrue(DTLS13UnifiedHeader.hasSeq16(firstByte));
        assertTrue(DTLS13UnifiedHeader.hasLength(firstByte));
        assertFalse(DTLS13UnifiedHeader.hasConnectionID(firstByte));
        assertTrue(DTLS13UnifiedHeader.matchesEpoch(firstByte, 3));
        assertEquals(datagram.length, 5 + TlsUtils.readUint16(datagram, 3));

        byte[] received = receive(server, 1000);
        assertNotNull(received);
        assertTrue(Arrays.areEqual(data, received));
    }

    public void testRoundTripBothDirectionsAllSuites() throws Exception
    {
        int[] suites = { CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_128_CCM_SHA256,
            CipherSuite.TLS_AES_128_CCM_8_SHA256 };
        int[] hashes = { CryptoHashAlgorithm.sha256, CryptoHashAlgorithm.sha384, CryptoHashAlgorithm.sha256,
            CryptoHashAlgorithm.sha256, CryptoHashAlgorithm.sha256 };

        for (int s = 0; s < suites.length; ++s)
        {
            setUpPair(suites[s], hashes[s]);

            for (int i = 0; i < 20; ++i)
            {
                byte[] data = new byte[i];
                RANDOM.nextBytes(data);
                client.recordLayer.send(data, 0, data.length);
                byte[] got = receive(server, 1000);
                assertNotNull("suite " + suites[s] + " len " + i, got);
                assertTrue(Arrays.areEqual(data, got));

                server.recordLayer.send(data, 0, data.length);
                got = receive(client, 1000);
                assertNotNull(got);
                assertTrue(Arrays.areEqual(data, got));
            }
        }
    }

    public void testReplayIsDropped() throws Exception
    {
        setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        byte[] data = new byte[10];
        client.recordLayer.send(data, 0, data.length);
        byte[] datagram = (byte[])clientToServer.peekLast().clone();
        assertNotNull(receive(server, 1000));

        clientToServer.put(datagram);
        assertNull(receive(server, 200));
    }

    public void testShortAndCorruptRecordsAreDroppedSilently() throws Exception
    {
        setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        // header claims 15 bytes of ciphertext: below the RFC 9147 4.2.3 minimum
        byte[] tooShort = new byte[5 + 15];
        tooShort[0] = (byte)0x2F;
        TlsUtils.writeUint16(15, tooShort, 3);
        clientToServer.put(tooShort);
        assertNull(receive(server, 200));

        // valid length but garbage ciphertext: fails authentication, must not throw
        byte[] garbage = new byte[5 + 40];
        garbage[0] = (byte)0x2F;
        TlsUtils.writeUint16(40, garbage, 3);
        RANDOM.nextBytes(garbage);
        garbage[0] = (byte)0x2F;
        TlsUtils.writeUint16(40, garbage, 3);
        clientToServer.put(garbage);
        assertNull(receive(server, 200));

        // unknown epoch bits (epoch 1) with the rest valid-looking
        byte[] wrongEpoch = new byte[5 + 40];
        wrongEpoch[0] = (byte)0x2D;
        TlsUtils.writeUint16(40, wrongEpoch, 3);
        clientToServer.put(wrongEpoch);
        assertNull(receive(server, 200));

        // the connection is still usable
        byte[] data = new byte[7];
        client.recordLayer.send(data, 0, data.length);
        assertTrue(Arrays.areEqual(data, receive(server, 1000)));
    }

    public void testMultipleRecordsInOneDatagram() throws Exception
    {
        setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        byte[] a = new byte[]{ 1, 2, 3 };
        byte[] b = new byte[]{ 4, 5, 6, 7 };
        client.recordLayer.send(a, 0, a.length);
        client.recordLayer.send(b, 0, b.length);

        byte[] d1 = clientToServer.take(100);
        byte[] d2 = clientToServer.take(100);
        clientToServer.put(Arrays.concatenate(d1, d2));

        assertTrue(Arrays.areEqual(a, receive(server, 1000)));
        assertTrue(Arrays.areEqual(b, receive(server, 1000)));
    }

    public void testApplicationDataAfterHandshakeWithRetransmitState() throws Exception
    {
        // A real handshake hands the record layer a retransmit handler, which retains the handshake epoch
        // (RFC 9147 5.8.1) for as long as a retransmitted final flight might still arrive. Drive that
        // retention through the harness itself - calling handshakeSuccessful a second time here would find
        // nothing left to retain, since the harness's own completed-handshake transition already cleared it.
        DTLSHandshakeRetransmit retransmit = new DTLSHandshakeRetransmit()
        {
            public void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len)
            {
            }
        };

        support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, retransmit, retransmit);
        clientToServer = support.clientToServer;
        serverToClient = support.serverToClient;
        client = support.client;
        server = support.server;

        // In DTLS 1.3 mode the retained handshake epoch must never become the write epoch: resetWriteEpoch
        // puts it there anyway (it is DTLS 1.2 only, guarded at its sole call site in
        // DTLSReliableHandshake.resendOutboundFlight by !isDTLS13()), so calling it directly here forces
        // exactly the state sendReturningRecordNumber's own dtls13 guard must not be fooled by.
        client.recordLayer.resetWriteEpoch();

        byte[] data = new byte[]{ 0x14, 0x15, 0x16 }; // first byte would parse as handshake type finished (20)
        client.recordLayer.send(data, 0, data.length);
        assertTrue(Arrays.areEqual(data, receive(server, 1000)));
    }

    /**
     * RFC 9147 5.8.1. The handshake epoch is held only for as long as a retransmission of the flight protected
     * under it may still arrive, so once the handshake has completed without that retention (or once it has
     * been dropped) nothing may resolve epoch 2 any more - neither to send at it, which would address a peer
     * that has long since moved on, nor by keeping its traffic keys and replay window alive for the life of
     * the connection.
     * <p>
     * The failure is raised rather than returned: silently declining to write a record of a retransmitted
     * flight truncates it into one the peer can never answer, which shows up only as a later timeout.
     * </p>
     */
    public void testHandshakeEpochIsNotHeldWithoutRetransmitState() throws Exception
    {
        setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        // setUpPair completes the handshake with no retransmit handler, so there is nothing to retain for
        byte[] data = new byte[]{ 0x14, 0x00, 0x00, 0x00 };

        try
        {
            client.recordLayer.sendHandshakeRecordAtEpoch(2, data, 0, data.length);
            fail("expected a fatal alert for a write at an epoch the record layer no longer holds");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.internal_error, e.getAlertDescription());
        }

        assertTrue("nothing may be written at an epoch that is no longer held", clientToServer.datagrams.isEmpty());
    }

    /**
     * A conforming peer may send the compact header forms even though we only ever write the full form, so the
     * receive path must handle them. The record is built by hand from a cipher keyed exactly like the client's
     * epoch-3 cipher and placed on the wire directly, bypassing client.recordLayer.send.
     */
    public void testCompactHeaderRecordIsReceived() throws Exception
    {
        setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        TlsDTLS13Cipher cipher = (TlsDTLS13Cipher)TlsUtils.initCipher(client.context);

        byte[] data = new byte[37];
        RANDOM.nextBytes(data);

        // S = 0, L = 1, epoch bits 11: a 4-byte header with an 8-bit sequence number
        long seq = 0;
        byte[] header = TlsAEADCipherDTLS13Test.compactHeader(0x24 | 0x03, seq);
        TlsEncodeResult encoded = cipher.encodeDTLS13Plaintext(seq, ContentType.application_data, header, 0,
            header.length, data, 0, data.length);

        byte[] datagram = Arrays.copyOfRange(encoded.buf, encoded.off, encoded.off + encoded.len);
        assertEquals(4 + TlsUtils.readUint16(datagram, 2), datagram.length);
        clientToServer.put(datagram);

        assertTrue(Arrays.areEqual(data, receive(server, 1000)));
    }

    /**
     * As above, but with no length field at all (S = 1, L = 0): the receiver must take the ciphertext as the
     * rest of the datagram.
     */
    public void testCompactHeaderRecordWithoutLengthIsReceived() throws Exception
    {
        setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        TlsDTLS13Cipher cipher = (TlsDTLS13Cipher)TlsUtils.initCipher(client.context);

        byte[] data = new byte[21];
        RANDOM.nextBytes(data);

        long seq = 0;
        byte[] header = TlsAEADCipherDTLS13Test.compactHeader(0x28 | 0x03, seq);
        assertEquals(3, header.length);
        TlsEncodeResult encoded = cipher.encodeDTLS13Plaintext(seq, ContentType.application_data, header, 0,
            header.length, data, 0, data.length);

        clientToServer.put(Arrays.copyOfRange(encoded.buf, encoded.off, encoded.off + encoded.len));

        assertTrue(Arrays.areEqual(data, receive(server, 1000)));
    }

    public void testLegacyHeaderPlaintextStillAcceptedAtEpochZero() throws Exception
    {
        // A DTLS 1.3 record layer still exchanges legacy-format plaintext records before keys exist; this
        // guards the epoch-0 path used by ClientHello/ServerHello.
        TlsCrypto crypto = new BcTlsCrypto();
        DTLSRecordLayer13TestSupport.Queue c2s = new DTLSRecordLayer13TestSupport.Queue();
        DTLSRecordLayer13TestSupport.Queue s2c = new DTLSRecordLayer13TestSupport.Queue();
        AbstractTlsContext context = TlsAEADCipherDTLS13Test.createContext(crypto, true,
            CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, new byte[32], new byte[32]);
        TlsPeer peer = new DefaultTlsClient(crypto)
        {
            public TlsAuthentication getAuthentication()
            {
                return null;
            }
        };
        DTLSRecordLayer serverLayer = new DTLSRecordLayer(context, peer,
            new DTLSRecordLayer13TestSupport.QueueTransport(c2s, s2c));
        serverLayer.setReadVersion(ProtocolVersion.DTLSv12);

        byte[] body = new byte[]{ HandshakeType.client_hello, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0 };
        byte[] record = new byte[13 + body.length];
        record[0] = (byte)ContentType.handshake;
        TlsUtils.writeVersion(ProtocolVersion.DTLSv12, record, 1);
        TlsUtils.writeUint16(0, record, 3);
        TlsUtils.writeUint48(0, record, 5);
        TlsUtils.writeUint16(body.length, record, 11);
        System.arraycopy(body, 0, record, 13, body.length);
        c2s.put(record);

        byte[] buf = new byte[serverLayer.getReceiveLimit()];
        int n = serverLayer.receive(buf, 0, buf.length, 1000);
        assertEquals(body.length, n);
        assertTrue(Arrays.areEqual(body, Arrays.copyOf(buf, n)));
    }

    public void testCiphertextRecordClaimingEpochZeroIsDiscarded() throws Exception
    {
        // A DTLSCiphertext record's epoch bits can alias epoch 0 (only the low two bits are on the wire) while
        // the read side is still on the epoch-0 null cipher, i.e. after initPendingEpoch but before
        // enablePendingEpochRead. That must be a handled discard (-1), not an unchecked ClassCastException.
        TlsCrypto crypto = new BcTlsCrypto();
        DTLSRecordLayer13TestSupport.Queue c2s = new DTLSRecordLayer13TestSupport.Queue();
        DTLSRecordLayer13TestSupport.Queue s2c = new DTLSRecordLayer13TestSupport.Queue();
        AbstractTlsContext context = TlsAEADCipherDTLS13Test.createContext(crypto, true,
            CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, new byte[32], new byte[32]);
        TlsPeer peer = new DefaultTlsClient(crypto)
        {
            public TlsAuthentication getAuthentication()
            {
                return null;
            }
        };
        DTLSRecordLayer serverLayer = new DTLSRecordLayer(context, peer,
            new DTLSRecordLayer13TestSupport.QueueTransport(c2s, s2c));
        serverLayer.setWriteVersion(ProtocolVersion.DTLSv12);
        serverLayer.setReadVersion(ProtocolVersion.DTLSv12);

        // Puts the record layer into DTLS 1.3 mode (dtls13 == true) without moving the read epoch off epoch 0.
        serverLayer.initPendingEpoch(TlsUtils.initCipher(context));
        assertEquals(2, serverLayer.getPendingEpoch());
        assertEquals(0, serverLayer.getReadEpoch());

        // firstByte 0x2C: fixed bits 001, C=0, S=1, L=1, EE=00 -> matches epoch 0's low two bits.
        int headerLength = 5;
        int ciphertextLength = DTLS13UnifiedHeader.MIN_CIPHERTEXT_LENGTH;
        byte[] record = new byte[headerLength + ciphertextLength];
        record[0] = (byte)0x2C;
        TlsUtils.writeUint16(ciphertextLength, record, 3);
        c2s.put(record);

        byte[] buf = new byte[serverLayer.getReceiveLimit()];
        int n = serverLayer.receive(buf, 0, buf.length, 1000);
        assertEquals(-1, n);
    }
}
