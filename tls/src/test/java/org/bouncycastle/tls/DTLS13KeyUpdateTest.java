package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsDTLS13Cipher;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * RFC 9147 8, the receiving half of a post-handshake key update: a peer's KeyUpdate installs the next read
 * epoch, keyed from the peer's updated traffic secret, and the epoch it supersedes stays readable until the
 * first record decrypts under the new one.
 * <p>
 * The two halves of section 8 have different triggers, and both are covered here. The sender may not write at
 * its new epoch until its own KeyUpdate has been <em>acknowledged</em>; the receiver may not release the
 * pre-update keys until the first successful <em>decryption</em> at the new epoch. A test of one half must
 * never turn on the other's trigger, and the names say which half each one is about.
 * </p>
 * <p>
 * {@link DTLSRecordLayerEpochSetTest} deliberately keys the epochs it compares identically, so that the epoch
 * number on the wire is the only thing distinguishing two records. That isolates the numbering but proves
 * nothing about the keys, which is the gap {@link #testNewReadEpochIsKeyedFromAnUpdatedSecret()} closes: it
 * would fail if the key schedule handed back the material it was given.
 * </p>
 */
public class DTLS13KeyUpdateTest
    extends TestCase
{
    private static final int MAX_HANDSHAKE_MESSAGE_SIZE = 1 << 14;

    /** The application epoch both directions reach when the handshake completes (RFC 9147 6.1). */
    private static final int APPLICATION_EPOCH = 3;

    /** {@link AbstractTlsPeer#getHandshakeResendTimeMillis()}, which the harness's peers do not override. */
    private static final int DEFAULT_RESEND_MILLIS = 1000;

    private DTLSRecordLayer13TestSupport support;
    private DTLSRecordLayer13TestSupport.Side client, server;

    private void setUpPair() throws IOException
    {
        support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);
        client = support.client;
        server = support.server;

        client.recordLayer.initPostHandshake(0, 0, MAX_HANDSHAKE_MESSAGE_SIZE);
        server.recordLayer.initPostHandshake(0, 0, MAX_HANDSHAKE_MESSAGE_SIZE);
    }

    /** One complete KeyUpdate handshake message, as the client would put it in a record. */
    private static byte[] keyUpdate(int messageSeq, short requestUpdate)
    {
        byte[] message = new byte[DTLSReliableHandshake.MESSAGE_HEADER_LENGTH + 1];
        TlsUtils.writeUint8(HandshakeType.key_update, message, 0);
        TlsUtils.writeUint24(1, message, 1);
        TlsUtils.writeUint16(messageSeq, message, 4);
        TlsUtils.writeUint24(0, message, 6);
        TlsUtils.writeUint24(1, message, 9);
        TlsUtils.writeUint8(requestUpdate, message, 12);
        return message;
    }

    private DTLSRecordNumber sendKeyUpdate(int messageSeq, short requestUpdate) throws IOException
    {
        byte[] message = keyUpdate(messageSeq, requestUpdate);
        return client.recordLayer.sendRecordForTest(ContentType.handshake, message, 0, message.length);
    }

    /**
     * The client's side of the same key update: its local traffic secret is updated and the write epoch it
     * keys is derived and installed at once. Section 8 would have the sender wait for our ACK before
     * installing; that gate is the sending half's and not what is under test here, so the wait is skipped and
     * the epoch installed directly, which is the only way to get records under the new keys onto the wire.
     */
    private void clientMovesToTheNextWriteEpoch() throws IOException
    {
        TlsUtils.update13TrafficSecretLocal(client.context);

        client.recordLayer.derivePendingWriteEpoch(TlsUtils.initCipher(client.context));
        client.recordLayer.installPendingWriteEpoch();
    }

    /** Remove and return the single datagram the client has queued. */
    private byte[] takeClientDatagram() throws IOException
    {
        byte[] datagram = support.clientToServer.take(0);
        assertNotNull("expected exactly one queued client datagram", datagram);
        assertNull("expected exactly one queued client datagram", support.clientToServer.take(0));
        return datagram;
    }

    /** Remove every datagram the client has queued, in the order it sent them. */
    private Vector takeClientDatagrams() throws IOException
    {
        Vector datagrams = new Vector();
        for (;;)
        {
            byte[] datagram = support.clientToServer.take(0);
            if (null == datagram)
            {
                return datagrams;
            }
            datagrams.addElement(datagram);
        }
    }

    /**
     * Hand the server exactly one datagram and let it process it, so that the delivery order is the test's to
     * choose rather than the order the records were produced in.
     *
     * @return the application data the record carried, or null if the record produced none - which covers
     *         both a record the server handled internally (a KeyUpdate) and a record it dropped.
     */
    private byte[] deliver(byte[] datagram) throws IOException
    {
        support.clientToServer.put(datagram);
        return DTLSRecordLayer13TestSupport.receive(server, 100);
    }

    private static int[] epochNumbers(DTLSRecordLayer recordLayer)
    {
        Vector liveReadEpochs = recordLayer.getLiveReadEpochs();
        int[] result = new int[liveReadEpochs.size()];
        for (int i = 0; i < result.length; ++i)
        {
            result[i] = ((DTLSEpoch)liveReadEpochs.elementAt(i)).getEpoch();
        }
        return result;
    }

    private static TlsDTLS13Cipher cipherOfLiveReadEpoch(DTLSRecordLayer recordLayer, int index)
    {
        DTLSEpoch epoch = (DTLSEpoch)recordLayer.getLiveReadEpochs().elementAt(index);
        return (TlsDTLS13Cipher)epoch.getCipher();
    }

    /**
     * Decode a captured record with a given cipher, the way {@code processDTLS13Record} does but with the
     * sequence number supplied rather than reconstructed - so that a failure is the AEAD's and not a mistake
     * about which record number the sender used.
     *
     * @return the decoded plaintext, or null if the cipher could not decrypt the record.
     */
    private static byte[] decodeWith(TlsDTLS13Cipher cipher, byte[] record, long seqNo)
    {
        // decryptDTLS13RecordNumber works in place, so each attempt gets its own copy
        byte[] copy = Arrays.clone(record);

        try
        {
            int firstByte = copy[0] & 0xFF;
            int headerLength = DTLS13UnifiedHeader.getHeaderLength(firstByte, 0);

            cipher.decryptDTLS13RecordNumber(copy, 0, copy.length);

            int ciphertextLength = DTLS13UnifiedHeader.hasLength(firstByte)
                ? TlsUtils.readUint16(copy, headerLength - 2)
                : copy.length - headerLength;

            TlsDecodeResult decoded = cipher.decodeDTLS13Ciphertext(seqNo, copy, 0, headerLength,
                ciphertextLength);

            return Arrays.copyOfRange(decoded.buf, decoded.off, decoded.off + decoded.len);
        }
        catch (IOException e)
        {
            return null;
        }
    }

    /**
     * RFC 9147 8. A peer's KeyUpdate moves our read side: the next read epoch is installed and the epoch it
     * supersedes is retained. The write side does not move - the two directions advance on their own key
     * updates - and the record is still acknowledged, which is what the peer is waiting for.
     */
    public void testPeerKeyUpdateInstallsTheNextReadEpoch() throws Exception
    {
        setUpPair();

        assertTrue(Arrays.areEqual(new int[]{ APPLICATION_EPOCH }, epochNumbers(server.recordLayer)));
        assertEquals(-1, server.recordLayer.getRetainedReadEpoch());

        DTLSRecordNumber sent = sendKeyUpdate(0, KeyUpdateRequest.update_not_requested);
        assertEquals(APPLICATION_EPOCH, sent.getEpoch());

        assertNull(deliver(takeClientDatagram()));

        assertEquals(1, server.recordLayer.getPostHandshake().getKeyUpdateCount());
        assertEquals("the read side moves to the next epoch", 4, server.recordLayer.getReadEpoch());
        assertEquals("the epoch it supersedes is retained", APPLICATION_EPOCH,
            server.recordLayer.getRetainedReadEpoch());
        assertTrue("newest first, with the retained epoch below the current read epoch",
            Arrays.areEqual(new int[]{ 4, APPLICATION_EPOCH }, epochNumbers(server.recordLayer)));

        /*
         * The write side is untouched: the epoch numbers are per-direction, so our next write epoch is still
         * 4 and not 5, and an ACK of the KeyUpdate goes out at the epoch we are still writing at.
         */
        assertEquals(4, server.recordLayer.derivePendingWriteEpoch(TlsUtils.initCipher(server.context))
            .getEpoch());
        assertFalse("the KeyUpdate record is acknowledged", support.serverToClient.datagrams.isEmpty());
    }

    /**
     * RFC 9147 8, both halves of the retention rule. "receivers MUST retain the pre-update keying material
     * until receipt and successful decryption of a message using the new keys."
     * <p>
     * A record the peer had already put on the wire under the old epoch, arriving after the new read epoch is
     * installed but before anything has decrypted under it, must still be readable - otherwise a reordered or
     * delayed record costs real application data. After a record has decrypted at the new epoch, the same
     * old-epoch traffic must be dropped.
     * </p>
     * <p>
     * Mutations this test is built to catch: drop the {@code retainReadEpoch} call from
     * {@code updatePeerReadEpoch} and the first half fails (the pre-update record is dropped immediately);
     * remove the {@code releaseRetainedReadEpoch} call from {@code processDTLS13Record} and the second half
     * fails (the old epoch is still readable after the release should have happened). Moving the release from
     * the decryption to, say, the ACK of the KeyUpdate also fails the first half, since that ACK is sent
     * before either old-epoch record arrives.
     * </p>
     */
    public void testRetainedReadEpochIsReadableUntilARecordDecryptsAtTheNewEpoch() throws Exception
    {
        setUpPair();

        byte[] oldBefore = new byte[]{ 0x01, 0x02, 0x03, 0x04 };
        byte[] oldAfter = new byte[]{ 0x05, 0x06, 0x07, 0x08 };
        byte[] atNewEpoch = new byte[]{ 0x09, 0x0a, 0x0b, 0x0c };

        sendKeyUpdate(0, KeyUpdateRequest.update_not_requested);

        // Two more records under the old epoch, both already on the wire when the KeyUpdate is processed
        DTLSRecordNumber beforeNumber = client.recordLayer.sendReturningRecordNumber(oldBefore, 0,
            oldBefore.length);
        DTLSRecordNumber afterNumber = client.recordLayer.sendReturningRecordNumber(oldAfter, 0,
            oldAfter.length);
        assertEquals(APPLICATION_EPOCH, beforeNumber.getEpoch());
        assertEquals(APPLICATION_EPOCH, afterNumber.getEpoch());

        clientMovesToTheNextWriteEpoch();

        DTLSRecordNumber newNumber = client.recordLayer.sendReturningRecordNumber(atNewEpoch, 0,
            atNewEpoch.length);
        assertEquals(4, newNumber.getEpoch());

        Vector datagrams = takeClientDatagrams();
        assertEquals(4, datagrams.size());

        assertNull(deliver((byte[])datagrams.elementAt(0)));
        assertEquals(4, server.recordLayer.getReadEpoch());
        assertEquals(APPLICATION_EPOCH, server.recordLayer.getRetainedReadEpoch());

        byte[] received = deliver((byte[])datagrams.elementAt(1));
        assertNotNull("a record under the pre-update epoch must still be readable", received);
        assertTrue(Arrays.areEqual(oldBefore, received));
        assertEquals("reading at the old epoch is not the release trigger", APPLICATION_EPOCH,
            server.recordLayer.getRetainedReadEpoch());

        received = deliver((byte[])datagrams.elementAt(3));
        assertNotNull("a record under the new epoch must be readable", received);
        assertTrue(Arrays.areEqual(atNewEpoch, received));
        assertEquals("a successful decryption at the new epoch releases the retained one", -1,
            server.recordLayer.getRetainedReadEpoch());
        assertTrue(Arrays.areEqual(new int[]{ 4 }, epochNumbers(server.recordLayer)));

        assertNull("the pre-update epoch must be gone, not merely unused",
            deliver((byte[])datagrams.elementAt(2)));
    }

    /**
     * The new read epoch is keyed from an <em>updated</em> traffic secret, not merely numbered one higher. A
     * record encrypted under the pre-update keys cannot be read at the new epoch and one encrypted under the
     * new keys cannot be read at the old, which is the property the epoch-number tests cannot see: they key
     * both epochs identically on purpose.
     * <p>
     * Both directions are asserted because only one of them fails on its own if the ciphers are aliased. The
     * decoding here is done by the ciphers directly rather than over the wire, because on the wire the two
     * records carry different epoch bits and would be told apart by their numbering whatever their keys.
     * </p>
     * <p>
     * Mutation this test is built to catch: have {@code updatePeerReadEpoch} build the new epoch's cipher
     * without calling {@code update13TrafficSecretPeer} first (or reuse the superseded epoch's cipher
     * object), and each of the two "must not" assertions fails.
     * </p>
     */
    public void testNewReadEpochIsKeyedFromAnUpdatedSecret() throws Exception
    {
        setUpPair();

        byte[] underOldKeys = new byte[]{ 0x11, 0x22, 0x33, 0x44 };
        byte[] underNewKeys = new byte[]{ 0x55, 0x66, 0x77, (byte)0x88 };

        DTLSRecordNumber oldNumber = client.recordLayer.sendReturningRecordNumber(underOldKeys, 0,
            underOldKeys.length);
        byte[] oldRecord = takeClientDatagram();

        sendKeyUpdate(0, KeyUpdateRequest.update_not_requested);
        assertNull(deliver(takeClientDatagram()));
        assertEquals(4, server.recordLayer.getReadEpoch());

        clientMovesToTheNextWriteEpoch();

        DTLSRecordNumber newNumber = client.recordLayer.sendReturningRecordNumber(underNewKeys, 0,
            underNewKeys.length);
        byte[] newRecord = takeClientDatagram();

        TlsDTLS13Cipher newCipher = cipherOfLiveReadEpoch(server.recordLayer, 0);
        TlsDTLS13Cipher oldCipher = cipherOfLiveReadEpoch(server.recordLayer, 1);

        byte[] decoded = decodeWith(oldCipher, oldRecord, oldNumber.getSequenceNumber());
        assertNotNull("the retained epoch must still decrypt what it was keyed for", decoded);
        assertTrue(Arrays.areEqual(underOldKeys, decoded));

        assertNull("the new epoch must not be able to read the pre-update keys' output",
            decodeWith(newCipher, oldRecord, oldNumber.getSequenceNumber()));

        decoded = decodeWith(newCipher, newRecord, newNumber.getSequenceNumber());
        assertNotNull("the new epoch must decrypt what the updated secret keyed", decoded);
        assertTrue(Arrays.areEqual(underNewKeys, decoded));

        assertNull("the pre-update keys must not be able to read the new epoch's output",
            decodeWith(oldCipher, newRecord, newNumber.getSequenceNumber()));
    }

    /**
     * RFC 9147 8. The release happens on the decryption of the record, before the message it carries is
     * dispatched. That ordering is what lets a KeyUpdate be the very first thing to arrive at a new epoch -
     * a legitimate case, since our ACK is what frees the peer to send at the new epoch and it need not send
     * anything else first - without the retained slot from the previous update still being occupied.
     * <p>
     * Mutation this test is built to catch: move the release after {@code processDecodedRecord} and the
     * second update is refused with unexpected_message.
     * </p>
     */
    public void testKeyUpdateArrivingAtTheNewEpochReleasesTheRetainedOneFirst() throws Exception
    {
        setUpPair();

        sendKeyUpdate(0, KeyUpdateRequest.update_not_requested);
        assertNull(deliver(takeClientDatagram()));

        assertEquals(4, server.recordLayer.getReadEpoch());
        assertEquals(APPLICATION_EPOCH, server.recordLayer.getRetainedReadEpoch());

        clientMovesToTheNextWriteEpoch();

        DTLSRecordNumber second = sendKeyUpdate(1, KeyUpdateRequest.update_not_requested);
        assertEquals(4, second.getEpoch());
        assertNull(deliver(takeClientDatagram()));

        assertEquals(2, server.recordLayer.getPostHandshake().getKeyUpdateCount());
        assertEquals(5, server.recordLayer.getReadEpoch());
        assertEquals("the epoch the second update supersedes is the one it arrived at", 4,
            server.recordLayer.getRetainedReadEpoch());
        assertTrue(Arrays.areEqual(new int[]{ 5, 4 }, epochNumbers(server.recordLayer)));
    }

    /**
     * RFC 9147 8 forbids a peer sending a new KeyUpdate before the previous one has been acknowledged, and
     * our acknowledgement is followed by its records at the new epoch, which release the retained one. So a
     * second KeyUpdate still at the old epoch is the peer breaking that rule. Honouring it would mean either
     * discarding keys that records are still arriving under or letting the retained set grow at the peer's
     * discretion, so it is refused.
     */
    public void testSecondKeyUpdateAtTheOldEpochIsFatal() throws Exception
    {
        setUpPair();

        sendKeyUpdate(0, KeyUpdateRequest.update_not_requested);
        assertNull(deliver(takeClientDatagram()));

        assertEquals(APPLICATION_EPOCH, server.recordLayer.getRetainedReadEpoch());

        // still writing at the old epoch, so this record arrives under the retained one
        sendKeyUpdate(1, KeyUpdateRequest.update_not_requested);

        try
        {
            deliver(takeClientDatagram());
            fail("expected a second key update while a read epoch is retained to be refused");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.unexpected_message, e.getAlertDescription());
        }

        assertEquals("the refused update must not have moved the read side", 4,
            server.recordLayer.getReadEpoch());
        assertEquals(APPLICATION_EPOCH, server.recordLayer.getRetainedReadEpoch());
    }

    /**
     * RFC 8446 4.6.3. "If the request_update field is set to 'update_requested', then the receiver MUST send
     * a KeyUpdate of its own with request_update set to 'update_not_requested' prior to sending its next
     * Application Data record." The obligation is recorded, exactly as TlsProtocol.receive13KeyUpdate records
     * it, and the sending side answers it; nothing is sent from the receive path on either transport.
     */
    public void testUpdateRequestedRecordsAnObligationToAnswer() throws Exception
    {
        setUpPair();

        DTLS13PostHandshake postHandshake = server.recordLayer.getPostHandshake();
        assertFalse(postHandshake.isKeyUpdatePendingSend());

        sendKeyUpdate(0, KeyUpdateRequest.update_requested);
        assertNull(deliver(takeClientDatagram()));

        assertTrue("an update_requested must be answered", postHandshake.isKeyUpdatePendingSend());

        postHandshake.clearKeyUpdatePendingSend();
        assertFalse(postHandshake.isKeyUpdatePendingSend());
    }

    /**
     * The mirror of the above: an update_not_requested is answered with nothing. Our read side still moves -
     * that is not optional - but no KeyUpdate of our own is owed.
     */
    public void testUpdateNotRequestedRecordsNoObligation() throws Exception
    {
        setUpPair();

        sendKeyUpdate(0, KeyUpdateRequest.update_not_requested);
        assertNull(deliver(takeClientDatagram()));

        assertEquals(4, server.recordLayer.getReadEpoch());
        assertFalse("update_not_requested must not oblige us to send one",
            server.recordLayer.getPostHandshake().isKeyUpdatePendingSend());
    }

    /**
     * RFC 8446 4.6.3. A malformed KeyUpdate is refused before anything irreversible happens: the traffic
     * secret update destroys the secret it replaces, so starting it on a message that then turns out to be
     * rejected would leave the connection holding a read epoch nothing can be keyed for.
     */
    public void testMalformedKeyUpdateDoesNotTouchTheKeySchedule() throws Exception
    {
        setUpPair();

        byte[] message = keyUpdate(0, KeyUpdateRequest.update_not_requested);
        // an out-of-range KeyUpdateRequest, which is checked after the length and before anything is acted on
        TlsUtils.writeUint8((short)2, message, 12);

        client.recordLayer.sendRecordForTest(ContentType.handshake, message, 0, message.length);

        try
        {
            deliver(takeClientDatagram());
            fail("expected a fatal alert for an out-of-range KeyUpdateRequest");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.illegal_parameter, e.getAlertDescription());
        }

        assertEquals("a refused KeyUpdate must not have moved the read side", APPLICATION_EPOCH,
            server.recordLayer.getReadEpoch());
        assertEquals(-1, server.recordLayer.getRetainedReadEpoch());
    }

    /**
     * RFC 9147 8 caps a sending implementation's epoch at 2^48-1 and tells a receiving one not to enforce
     * that cap. Neither binds before the int a {@link DTLSEpoch} holds its epoch in does, and that is the
     * bound checked here: a key update is the one place where a peer influences how fast the number advances,
     * and a silent wrap would produce a negative epoch, or one aliasing an epoch already held.
     * <p>
     * Asserted against the helper directly: no connection can reach 2^31-1 key updates, each of which costs a
     * round trip, so a test that drove the record layer to it could not exist.
     * </p>
     */
    public void testEpochNumberOverflowIsRefused() throws Exception
    {
        assertEquals(4, DTLSRecordLayer.nextEpoch(3));
        assertEquals(Integer.MAX_VALUE, DTLSRecordLayer.nextEpoch(Integer.MAX_VALUE - 1));

        try
        {
            DTLSRecordLayer.nextEpoch(Integer.MAX_VALUE);
            fail("expected an epoch number overflow to be refused");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.internal_error, e.getAlertDescription());
        }
    }

    /**
     * Installing a write epoch advances 'currentEpoch' with it, so that once both directions have moved on,
     * the epoch number they left behind resolves for nothing.
     * <p>
     * 'currentEpoch' is what makes this reachable. Until a key update, both directions point at the one
     * DTLSEpoch object the handshake installed, so the epoch it numbers stays resolvable through whichever
     * direction has not yet moved; there is nothing stale about it. Once BOTH have moved and the retained
     * read epoch has been released, nothing holds that epoch except a 'currentEpoch' left behind - and
     * getEpochForRetransmit falls back to 'currentEpoch', so leaving it behind turns a released epoch into a
     * live lookup returning keys and a sequence number the connection has finished with.
     * </p>
     * <p>
     * Mutation this test is built to catch: drop the 'currentEpoch' assignment from
     * {@code installPendingWriteEpoch} and the superseded epoch number resolves again, so nothing is thrown
     * and a record goes out under it.
     * </p>
     */
    public void testEpochBothDirectionsHaveLeftResolvesForNothing() throws Exception
    {
        setUpPair();

        DTLSRecordLayer serverLayer = server.recordLayer;
        byte[] body = new byte[]{ 0x14, 0x00, 0x00, 0x00 };

        // The peer's key update moves the server's read side to 4, retaining 3
        sendKeyUpdate(0, KeyUpdateRequest.update_not_requested);
        assertNull(deliver(takeClientDatagram()));
        assertEquals(APPLICATION_EPOCH, serverLayer.getRetainedReadEpoch());

        // The server's own key update moves its write side to 4, independently of the read side's 4
        TlsUtils.update13TrafficSecretLocal(server.context);
        serverLayer.derivePendingWriteEpoch(TlsUtils.initCipher(server.context));
        assertEquals(4, serverLayer.installPendingWriteEpoch().getEpoch());

        // Still resolvable: the retained read epoch is exactly epoch 3
        assertEquals(APPLICATION_EPOCH, serverLayer.sendHandshakeRecordAtEpoch(APPLICATION_EPOCH, body, 0,
            body.length).getEpoch());

        // A record at the peer's new epoch releases the retained one, and now nothing holds epoch 3
        clientMovesToTheNextWriteEpoch();
        byte[] atNewEpoch = new byte[]{ 0x09, 0x0a, 0x0b, 0x0c };
        client.recordLayer.sendReturningRecordNumber(atNewEpoch, 0, atNewEpoch.length);
        assertTrue(Arrays.areEqual(atNewEpoch, deliver(takeClientDatagram())));
        assertEquals(-1, serverLayer.getRetainedReadEpoch());

        try
        {
            serverLayer.sendHandshakeRecordAtEpoch(APPLICATION_EPOCH, body, 0, body.length);
            fail("expected an epoch both directions have left to be unresolvable");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.internal_error, e.getAlertDescription());
        }
    }

    /**
     * A KeyUpdate is refused outright unless DTLS 1.3 was negotiated. RFC 9147 8 exists only there, and the
     * DTLS 1.2 record layer has no epoch machinery a key update could move.
     */
    public void testKeyUpdateRequiresDTLS13() throws Exception
    {
        setUpPair();

        DTLSRecordLayer legacyLayer = support.setUpLegacyLayer();
        assertFalse(legacyLayer.isDTLS13());

        try
        {
            legacyLayer.updatePeerReadEpoch();
            fail("expected a key update on a DTLS 1.2 record layer to be refused");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    /** The epoch number the low 2 bits of a sent record's first byte can be attributed to. */
    private static void assertSentAtEpoch(int expectedEpoch, int otherEpoch, byte[] datagram)
    {
        assertSentAtEpoch("record", expectedEpoch, otherEpoch, datagram);
    }

    private static void assertSentAtEpoch(String message, int expectedEpoch, int otherEpoch, byte[] datagram)
    {
        int firstByte = datagram[0] & 0xFF;
        assertTrue(message + " must be on the wire under epoch " + expectedEpoch,
            DTLS13UnifiedHeader.matchesEpoch(firstByte, expectedEpoch));
        assertFalse(message + " must not be on the wire under epoch " + otherEpoch,
            DTLS13UnifiedHeader.matchesEpoch(firstByte, otherEpoch));
    }

    /** Send one application record from the client and return the datagram it produced. */
    private byte[] sendClientApplicationData(byte[] data, int expectedEpoch) throws IOException
    {
        DTLSRecordNumber recordNumber = client.recordLayer.sendReturningRecordNumber(data, 0, data.length);
        assertNotNull(recordNumber);
        assertEquals(expectedEpoch, recordNumber.getEpoch());
        return takeClientDatagram();
    }

    /**
     * RFC 9147 8, the SENDING half. "implementations MUST NOT send records with the new keys ... until the
     * previous KeyUpdate has been acknowledged."
     * <p>
     * The acknowledgement is withheld, and every record sent meanwhile is read off the wire and checked for
     * the OLD epoch's bits - not asked of a field, and not decrypted, because a field assertion would pass
     * even if the send path had picked up the derived epoch, and a decryption would only prove which keys we
     * think we used. Then the ACK is delivered and the epoch advances, on the wire, in the same way.
     * </p>
     * <p>
     * Mutations this test is built to catch: install the derived epoch at the point the KeyUpdate is sent
     * (i.e. follow {@code deriveNextWriteEpoch} with {@code installPendingWriteEpoch} in
     * {@code sendKeyUpdate}) and every withheld-ACK assertion fails; drop the
     * {@code installPendingWriteEpoch} call from {@code receivedAck} and the post-ACK assertions fail.
     * </p>
     */
    public void testNoRecordIsSentAtTheNewEpochUntilTheKeyUpdateIsAcknowledged() throws Exception
    {
        setUpPair();

        DTLS13PostHandshake clientPostHandshake = client.recordLayer.getPostHandshake();
        assertFalse(clientPostHandshake.isKeyUpdateOutstanding());

        clientPostHandshake.sendKeyUpdate(KeyUpdateRequest.update_not_requested);

        assertTrue(clientPostHandshake.isKeyUpdateOutstanding());
        assertEquals(APPLICATION_EPOCH, clientPostHandshake.getKeyUpdateEpoch());
        assertEquals("the new epoch is derived but not installed", 4,
            client.recordLayer.getPendingWriteEpoch());
        assertEquals(APPLICATION_EPOCH, client.recordLayer.getWriteEpoch());

        byte[] keyUpdateDatagram = takeClientDatagram();
        assertSentAtEpoch(APPLICATION_EPOCH, 4, keyUpdateDatagram);

        // Everything sent while the ACK is withheld is on the wire under the old epoch
        for (int i = 0; i < 3; ++i)
        {
            byte[] data = new byte[]{ (byte)i, 0x02, 0x03, 0x04 };
            assertSentAtEpoch(APPLICATION_EPOCH, 4, sendClientApplicationData(data, APPLICATION_EPOCH));
            assertEquals(APPLICATION_EPOCH, client.recordLayer.getWriteEpoch());
            assertTrue(clientPostHandshake.isKeyUpdateOutstanding());
        }

        // Now let it be acknowledged: the peer processes the KeyUpdate and ACKs it, and we read that ACK
        assertNull(deliver(keyUpdateDatagram));
        assertEquals(4, server.recordLayer.getReadEpoch());
        assertFalse("the KeyUpdate must be acknowledged", support.serverToClient.datagrams.isEmpty());

        assertNull(DTLSRecordLayer13TestSupport.receive(client, 100));

        assertFalse("the acknowledgement ends the state machine", clientPostHandshake.isKeyUpdateOutstanding());
        assertEquals(4, client.recordLayer.getWriteEpoch());
        assertEquals(-1, client.recordLayer.getPendingWriteEpoch());

        byte[] afterAck = new byte[]{ 0x09, 0x0a, 0x0b, 0x0c };
        assertSentAtEpoch(4, APPLICATION_EPOCH, sendClientApplicationData(afterAck, 4));
    }

    /**
     * RFC 9147 8 and RFC 8446 5.5. A key update starts by itself once enough records have been sent under the
     * write epoch, at the same threshold the TLS record layer uses ({@code RecordStream.needsKeyUpdate}),
     * applied to the write epoch's sequence number.
     * <p>
     * The record that crosses the threshold still goes out at the old epoch. Starting a key update and moving
     * the epoch are different events, separated by the peer's acknowledgement.
     * </p>
     * <p>
     * Mutations this test is built to catch: raise {@code KEY_UPDATE_SEQUENCE_LIMIT} and the second half
     * fails (no update is started); lower it by one and the first half fails (one is started below the
     * threshold); test it against the read epoch's sequence number instead and both halves fail.
     * </p>
     */
    public void testKeyUpdateStartsAutomaticallyAtTheSequenceNumberThreshold() throws Exception
    {
        setUpPair();

        DTLS13PostHandshake clientPostHandshake = client.recordLayer.getPostHandshake();
        byte[] data = new byte[]{ 0x01, 0x02, 0x03, 0x04 };

        client.recordLayer.setWriteEpochSequenceNumberForTest((1L << 20) - 1);
        sendClientApplicationData(data, APPLICATION_EPOCH);
        assertFalse("below the threshold nothing is started", clientPostHandshake.isKeyUpdateOutstanding());
        assertEquals(-1, client.recordLayer.getPendingWriteEpoch());

        client.recordLayer.setWriteEpochSequenceNumberForTest(1L << 20);
        DTLSRecordNumber recordNumber = client.recordLayer.sendReturningRecordNumber(data, 0, data.length);

        assertTrue("at the threshold a key update is started", clientPostHandshake.isKeyUpdateOutstanding());
        assertEquals(APPLICATION_EPOCH, clientPostHandshake.getKeyUpdateEpoch());
        assertEquals(4, client.recordLayer.getPendingWriteEpoch());
        assertEquals("the record that crossed the threshold still goes out at the old epoch",
            APPLICATION_EPOCH, recordNumber.getEpoch());
        assertEquals(APPLICATION_EPOCH, client.recordLayer.getWriteEpoch());

        Vector datagrams = takeClientDatagrams();
        assertEquals("the KeyUpdate, then the application record", 2, datagrams.size());
        assertSentAtEpoch(APPLICATION_EPOCH, 4, (byte[])datagrams.elementAt(0));
        assertSentAtEpoch(APPLICATION_EPOCH, 4, (byte[])datagrams.elementAt(1));
    }

    /**
     * RFC 9147 5.8.4. The sending state machine "reduces to waiting for an ACK and retransmitting the
     * original message", and it is driven from the RECEIVE path. A peer that sends nothing after starting a
     * key update must still retransmit it, and must still install the new epoch when the ACK arrives - and
     * that peer is exactly the one a send-driven timer would never reach, because RFC 9147 8 has left it
     * unable to send anything new at the epoch it wants to use.
     * <p>
     * Nothing in this test writes application data after the KeyUpdate. The only calls that could produce the
     * retransmission are the receives.
     * </p>
     * <p>
     * Mutation this test is built to catch: drive {@code checkTimeouts} from {@code sendReturningRecordNumber}
     * instead of from {@code receive} and the retransmission never appears. The other half of the same
     * mechanism - that a blocking receive does not sleep past the resend timeout - is
     * {@link #testAReceiveBlocksNoLongerThanTheKeyUpdateResendTimeout()}, because this test brings the
     * timeout forward and so would not notice.
     * </p>
     */
    public void testAReceiveOnlyPeerRetransmitsItsKeyUpdateAndInstallsOnTheAck() throws Exception
    {
        setUpPair();

        DTLS13PostHandshake clientPostHandshake = client.recordLayer.getPostHandshake();
        clientPostHandshake.sendKeyUpdate(KeyUpdateRequest.update_not_requested);

        // The original is lost in transit, and the client sends nothing else for the rest of the test
        takeClientDatagram();

        clientPostHandshake.expireKeyUpdateResendTimeoutForTest();
        assertNull(DTLSRecordLayer13TestSupport.receive(client, 50));

        byte[] resent = takeClientDatagram();
        assertSentAtEpoch("the retransmission is at the epoch the peer can still read", APPLICATION_EPOCH,
            4, resent);
        assertTrue(clientPostHandshake.isKeyUpdateOutstanding());
        assertEquals(APPLICATION_EPOCH, client.recordLayer.getWriteEpoch());

        assertNull(deliver(resent));
        assertEquals("the retransmission is what moves the peer", 4, server.recordLayer.getReadEpoch());

        assertNull(DTLSRecordLayer13TestSupport.receive(client, 100));

        assertFalse(clientPostHandshake.isKeyUpdateOutstanding());
        assertEquals("a peer that never sent anything still reaches the new epoch", 4,
            client.recordLayer.getWriteEpoch());
    }

    /**
     * The other half of driving the state machine from the receive path: a receive must not block past the
     * resend timeout. The timeout here is the peer's real configured interval, not one brought forward, so a
     * receive whose wait is longer than it has to be cut short by it - otherwise a receive-only peer sleeps
     * through its own retransmission and the length of its stall is whatever its caller happened to pass.
     * <p>
     * Mutation this test is built to catch: drop the {@code constrainWaitMillis} call for
     * {@code postHandshake.getResendTimeout()} in {@code receive} and nothing is retransmitted within the
     * wait.
     * </p>
     */
    public void testAReceiveBlocksNoLongerThanTheKeyUpdateResendTimeout() throws Exception
    {
        setUpPair();

        DTLS13PostHandshake clientPostHandshake = client.recordLayer.getPostHandshake();
        clientPostHandshake.sendKeyUpdate(KeyUpdateRequest.update_not_requested);
        takeClientDatagram();

        assertNull(DTLSRecordLayer13TestSupport.receive(client, DEFAULT_RESEND_MILLIS
            + (DEFAULT_RESEND_MILLIS / 2)));

        byte[] resent = takeClientDatagram();
        assertSentAtEpoch("the retransmission", APPLICATION_EPOCH, 4, resent);
    }

    /**
     * RFC 9147 5.8.4. "implementations MUST NOT send KeyUpdate ... messages if an earlier message of the same
     * type has not yet been acknowledged." Neither an explicit request nor the automatic threshold starts a
     * second one.
     * <p>
     * Mutation this test is built to catch: remove the outstanding-message latch from
     * {@code checkKeyUpdateBeforeSend} and the automatic half fails - a second KeyUpdate goes out, and the
     * derivation behind it throws because there is nowhere to put a second epoch.
     * </p>
     */
    public void testASecondKeyUpdateIsNotStartedWhileOneIsOutstanding() throws Exception
    {
        setUpPair();

        DTLS13PostHandshake clientPostHandshake = client.recordLayer.getPostHandshake();
        clientPostHandshake.sendKeyUpdate(KeyUpdateRequest.update_not_requested);
        takeClientDatagrams();

        try
        {
            clientPostHandshake.sendKeyUpdate(KeyUpdateRequest.update_not_requested);
            fail("expected a second KeyUpdate to be refused while one is outstanding");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        client.recordLayer.setWriteEpochSequenceNumberForTest(1L << 20);
        byte[] data = new byte[]{ 0x01, 0x02, 0x03, 0x04 };
        client.recordLayer.sendReturningRecordNumber(data, 0, data.length);

        assertEquals("only the application record went out", 1, takeClientDatagrams().size());
        assertEquals("no second epoch was derived", 4, client.recordLayer.getPendingWriteEpoch());
        assertEquals(APPLICATION_EPOCH, clientPostHandshake.getKeyUpdateEpoch());
        assertEquals(APPLICATION_EPOCH, client.recordLayer.getWriteEpoch());
    }

    /**
     * RFC 9147 7. "After the handshake, implementations MUST use the highest available sending epoch" - and
     * that is the whole rule. The handshake-time floor ("an epoch equal to or higher than the record which is
     * being acknowledged") does not survive the handshake, and applying it afterwards is a real stall: the
     * two directions' epochs advance on their own key updates, so a peer that has updated its sending keys
     * while we have not sends its next KeyUpdate at an epoch above ours, and that KeyUpdate is a message
     * whose whole state machine is waiting for the ACK we would be withholding.
     * <p>
     * Reached here the way a connection reaches it: the peer key-updates twice, so its second KeyUpdate
     * arrives at epoch 4 while our own write epoch is still 3.
     * </p>
     * <p>
     * Mutation this test is built to catch: restore the unconditional epoch floor in {@code sendAck} and no
     * ACK is sent for the second KeyUpdate. The receive-side half is covered by
     * {@code testAnAckFromBelowOurEpochStillRetiresOurKeyUpdate}.
     * </p>
     */
    public void testAKeyUpdateAboveOurOwnWriteEpochIsStillAcknowledged() throws Exception
    {
        setUpPair();

        sendKeyUpdate(0, KeyUpdateRequest.update_not_requested);
        assertNull(deliver(takeClientDatagram()));
        assertFalse(support.serverToClient.datagrams.isEmpty());
        support.serverToClient.datagrams.removeAllElements();

        clientMovesToTheNextWriteEpoch();

        DTLSRecordNumber second = sendKeyUpdate(1, KeyUpdateRequest.update_not_requested);
        assertEquals("the peer's KeyUpdate is above our own write epoch", 4, second.getEpoch());
        assertEquals(APPLICATION_EPOCH, server.recordLayer.getWriteEpoch());

        assertNull(deliver(takeClientDatagram()));
        assertEquals(5, server.recordLayer.getReadEpoch());

        assertFalse("a KeyUpdate above our own write epoch must still be acknowledged",
            support.serverToClient.datagrams.isEmpty());
        assertSentAtEpoch("the ACK goes out at the highest epoch we have", APPLICATION_EPOCH, 4,
            support.serverToClient.peekLast());
    }

    /**
     * The receiving half of the same rule. Our KeyUpdate is sent at epoch 4 and the peer, still writing at
     * epoch 3, acknowledges it from below. That ACK must retire it: the record-number filter that discards
     * numbers above the ACK's own epoch is a handshake-time defence (a forged plaintext ACK at epoch 0), and
     * applying it to a protected post-handshake ACK leaves us retransmitting a KeyUpdate that has in fact
     * been acknowledged, forever.
     * <p>
     * Mutation this test is built to catch: filter unconditionally in the ACK receive path and the write
     * epoch never advances.
     * </p>
     */
    public void testAnAckFromBelowOurEpochStillRetiresOurKeyUpdate() throws Exception
    {
        setUpPair();

        DTLS13PostHandshake clientPostHandshake = client.recordLayer.getPostHandshake();

        // First key update, acknowledged at the same epoch, leaves the client writing at 4
        clientPostHandshake.sendKeyUpdate(KeyUpdateRequest.update_not_requested);
        assertNull(deliver(takeClientDatagram()));
        assertNull(DTLSRecordLayer13TestSupport.receive(client, 100));
        assertEquals(4, client.recordLayer.getWriteEpoch());

        // Second key update, sent at 4, while the server is still writing at 3
        clientPostHandshake.sendKeyUpdate(KeyUpdateRequest.update_not_requested);
        byte[] datagram = takeClientDatagram();
        assertSentAtEpoch(4, APPLICATION_EPOCH, datagram);

        assertNull(deliver(datagram));
        assertEquals(APPLICATION_EPOCH, server.recordLayer.getWriteEpoch());
        assertFalse(support.serverToClient.datagrams.isEmpty());

        assertNull(DTLSRecordLayer13TestSupport.receive(client, 100));

        assertFalse("an ACK from below our epoch still acknowledges our KeyUpdate",
            clientPostHandshake.isKeyUpdateOutstanding());
        assertEquals(5, client.recordLayer.getWriteEpoch());
    }

    /**
     * RFC 9147 8 and 4.2.2. An epoch built from the PEER's updated traffic secret may be read at and must
     * never be written at: a {@link DTLSEpoch} carries one cipher and one sequence number counter for both
     * directions, so writing at it would encrypt our records under the peer's key at sequence numbers the
     * peer has already used.
     * <p>
     * It is reachable only by number collision, which is why it is worth a test of its own: the two
     * directions start from the same application epoch and advance by one on their own key updates, so the
     * peer's read epoch 4 and a write-side request for "epoch 4" coincide as a matter of course.
     * </p>
     * <p>
     * Mutation this test is built to catch: drop the {@code isPeerKeyed} test from
     * {@code getEpochForRetransmit} and the peer's epoch is returned and written at.
     * </p>
     */
    public void testAPeerKeyedEpochIsNeverResolvedForWriting() throws Exception
    {
        setUpPair();

        byte[] body = new byte[]{ 0x14, 0x00, 0x00, 0x00 };

        // The peer's key update gives the server a read epoch 4 that is keyed from the PEER's secret
        sendKeyUpdate(0, KeyUpdateRequest.update_not_requested);
        assertNull(deliver(takeClientDatagram()));
        assertEquals(4, server.recordLayer.getReadEpoch());
        assertEquals(APPLICATION_EPOCH, server.recordLayer.getWriteEpoch());

        try
        {
            server.recordLayer.sendHandshakeRecordAtEpoch(4, body, 0, body.length);
            fail("expected an epoch keyed from the peer's secret to be unresolvable for writing");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.internal_error, e.getAlertDescription());
        }

        // Our own epoch 4, once we have one, resolves as it always did
        TlsUtils.update13TrafficSecretLocal(server.context);
        server.recordLayer.derivePendingWriteEpoch(TlsUtils.initCipher(server.context));
        assertEquals(4, server.recordLayer.installPendingWriteEpoch().getEpoch());

        assertEquals(4, server.recordLayer.sendHandshakeRecordAtEpoch(4, body, 0, body.length).getEpoch());
    }

}
