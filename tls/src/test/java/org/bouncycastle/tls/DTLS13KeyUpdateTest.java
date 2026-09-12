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
 * The two halves of section 8 have different triggers and only one of them is implemented here. The sender
 * may not write at its new epoch until its own KeyUpdate has been <em>acknowledged</em>; the receiver may not
 * release the pre-update keys until the first successful <em>decryption</em> at the new epoch. Nothing in
 * this class turns on an ACK.
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
}
