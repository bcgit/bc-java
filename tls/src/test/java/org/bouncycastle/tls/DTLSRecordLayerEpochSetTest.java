package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * RFC 9147 4.2.2 and 8. The record layer resolves a received record's epoch from one ordered collection of
 * live read epochs, iterated most recent first, and writes at an epoch through the same collection.
 * <p>
 * The load-bearing test here is {@link #testAliasingEpochResolvesToTheMostRecentMatch()}: only the low 2
 * epoch bits are on the wire, so two live epochs can alias, and the RFC resolves that to the most recent of
 * them. That test fails if the iteration order in {@code getLiveReadEpochs} is reversed - which is the only
 * thing that makes it a test of the order rather than of the lookup.
 * </p>
 */
public class DTLSRecordLayerEpochSetTest
    extends TestCase
{
    /** Records the epoch a post-handshake handshake record was attributed to. */
    private static class RecordingRetransmit
        implements DTLSHandshakeRetransmit
    {
        int epoch = -1;
        int count = 0;

        public void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len)
        {
            this.epoch = epoch;
            this.count++;
        }
    }

    private DTLSRecordLayer13TestSupport support;
    private RecordingRetransmit clientRetransmit;

    /**
     * A pair whose handshakes complete with a retransmit handler on each side, so that each side retains the
     * handshake epoch (RFC 9147 5.8.1) and the client additionally retains the plaintext epoch 0.
     */
    private void setUpPairWithRetainedEpochs() throws IOException
    {
        clientRetransmit = new RecordingRetransmit();

        support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, clientRetransmit,
            new RecordingRetransmit());
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

    private static DTLSEpoch liveReadEpoch(DTLSRecordLayer recordLayer, int index)
    {
        return (DTLSEpoch)recordLayer.getLiveReadEpochs().elementAt(index);
    }

    /**
     * An epoch built with a cipher keyed exactly like the side's own, so that it can decode the same records
     * its real epochs can. That is what lets a test tell which of two aliasing epochs a record resolved to:
     * both can decode it, so only the resolution order decides which one does.
     */
    private static DTLSEpoch createAliasEpoch(DTLSRecordLayer13TestSupport.Side side, int epoch)
        throws IOException
    {
        DTLSEpoch readEpoch = liveReadEpoch(side.recordLayer, 0);

        return new DTLSEpoch(epoch, TlsUtils.initCipher(side.context), readEpoch.getRecordHeaderLengthRead(),
            readEpoch.getRecordHeaderLengthWrite());
    }

    /**
     * The collection is ordered most recent first: the current read epoch, then anything retained across a key
     * update, then the handshake epoch, then - on the client only - the plaintext epoch 0.
     */
    public void testLiveReadEpochsAreOrderedMostRecentFirst() throws Exception
    {
        setUpPairWithRetainedEpochs();

        int[] clientEpochs = epochNumbers(support.client.recordLayer);
        assertEquals(3, clientEpochs.length);
        assertEquals(3, clientEpochs[0]);
        assertEquals(2, clientEpochs[1]);
        assertEquals(0, clientEpochs[2]);

        // Epoch 0 is unauthenticated and only the client has a reason to read it, so the server does not hold it
        int[] serverEpochs = epochNumbers(support.server.recordLayer);
        assertEquals(2, serverEpochs.length);
        assertEquals(3, serverEpochs[0]);
        assertEquals(2, serverEpochs[1]);

        DTLSEpoch retained = createAliasEpoch(support.client, 6);
        support.client.recordLayer.retainReadEpoch(retained);

        int[] afterRetain = epochNumbers(support.client.recordLayer);
        assertEquals(4, afterRetain.length);
        assertEquals(3, afterRetain[0]);
        assertEquals("a retained pre-update read epoch ranks below the current read epoch and above the rest",
            6, afterRetain[1]);
        assertEquals(2, afterRetain[2]);
        assertEquals(0, afterRetain[3]);
    }

    /**
     * RFC 9147 4.2.2: "the most recent past epoch which has matching bits". Epochs 6 and 2 share the low 2
     * bits that are on the wire, and both are live and able to decode the record, so the only thing that
     * decides which one the record is attributed to is the order the collection is iterated in.
     * <p>
     * Mutation this test is built to catch: reverse the iteration in {@code getLiveReadEpochs} (or in its
     * consumer in {@code processDTLS13Record}) and the record resolves to epoch 2 instead, failing every
     * assertion below.
     * </p>
     */
    public void testAliasingEpochResolvesToTheMostRecentMatch() throws Exception
    {
        setUpPairWithRetainedEpochs();

        DTLSRecordLayer clientLayer = support.client.recordLayer;

        // The client's retained handshake epoch, which epoch 6 will alias: 6 & 3 == 2 & 3
        DTLSEpoch handshakeEpoch = liveReadEpoch(clientLayer, 1);
        assertEquals(2, handshakeEpoch.getEpoch());

        DTLSEpoch retained = createAliasEpoch(support.client, 6);
        clientLayer.retainReadEpoch(retained);

        // A record the server sends at epoch 2 therefore reaches the client with epoch bits that match both
        byte[] body = new byte[]{ 0x14, 0x00, 0x00, 0x00 };
        support.server.recordLayer.sendHandshakeRecordAtEpoch(2, body, 0, body.length);

        DTLSRecordLayer13TestSupport.receive(support.client, 200);

        assertEquals("the record must be attributed to exactly one epoch", 1, clientRetransmit.count);
        assertEquals("an aliasing record resolves to the most recent matching epoch", 6, clientRetransmit.epoch);

        assertEquals("the most recent matching epoch consumed the record", 0,
            retained.getReplayWindow().getLatestConfirmedSeq());
        assertEquals("an older aliasing epoch must not have seen the record", -1,
            handshakeEpoch.getReplayWindow().getLatestConfirmedSeq());
    }

    /**
     * The read and the write sides resolve through the same collection, so an epoch that can be read can also
     * be written at. Before the refactor the two sides probed separate lists of fields and could disagree.
     */
    public void testRetainedReadEpochIsAlsoResolvedForWriting() throws Exception
    {
        setUpPairWithRetainedEpochs();

        DTLSRecordLayer clientLayer = support.client.recordLayer;

        DTLSEpoch retained = createAliasEpoch(support.client, 6);
        clientLayer.retainReadEpoch(retained);

        byte[] body = new byte[]{ 0x14, 0x00, 0x00, 0x00 };
        DTLSRecordNumber recordNumber = clientLayer.sendHandshakeRecordAtEpoch(6, body, 0, body.length);

        assertNotNull(recordNumber);
        assertEquals(6, recordNumber.getEpoch());
        assertFalse(support.clientToServer.datagrams.isEmpty());
    }

    /**
     * RFC 9147 8 forbids sending at a new epoch until the peer's KeyUpdate has been acknowledged, so a second
     * key update cannot begin while the first update's epoch is still retained. The bound is asserted rather
     * than assumed: an unbounded set driven by peer-controlled key updates is a memory-growth denial of
     * service.
     */
    public void testAtMostOneRetainedReadEpoch() throws Exception
    {
        setUpPairWithRetainedEpochs();

        DTLSRecordLayer clientLayer = support.client.recordLayer;

        clientLayer.retainReadEpoch(createAliasEpoch(support.client, 4));

        try
        {
            clientLayer.retainReadEpoch(createAliasEpoch(support.client, 5));
            fail("expected a second retained read epoch to be refused");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        int[] epochs = epochNumbers(clientLayer);
        assertEquals("the live read epoch set stays bounded", 4, epochs.length);
        assertEquals(4, epochs[1]);
    }

    /**
     * A cipher keyed exactly as the side's current one. A key update would key the new epoch from an updated
     * traffic secret, but nothing here depends on the keys differing - what is under test is which epoch a
     * record is sent under, and keeping the keys identical means the epoch number on the wire is the only
     * thing that can distinguish the two records.
     */
    private static TlsCipher createEpochCipher(DTLSRecordLayer13TestSupport.Side side) throws IOException
    {
        return TlsUtils.initCipher(side.context);
    }

    /** The epoch number the low 2 bits of a sent record's first byte can be attributed to. */
    private static void assertSentAtEpoch(int expectedEpoch, int otherEpoch, byte[] datagram)
    {
        int firstByte = datagram[0] & 0xFF;
        assertTrue("record must be on the wire under epoch " + expectedEpoch,
            DTLS13UnifiedHeader.matchesEpoch(firstByte, expectedEpoch));
        assertFalse("record must not be on the wire under epoch " + otherEpoch,
            DTLS13UnifiedHeader.matchesEpoch(firstByte, otherEpoch));
    }

    /**
     * RFC 9147 8: a key update MUST NOT send under the new epoch until the peer has acknowledged the
     * KeyUpdate, but the new epoch's cipher has to be built at the moment the KeyUpdate is generated, because
     * updating the traffic secret destroys the one the old epoch was keyed from. So the epoch is derived and
     * held, and only installing it may change what goes on the wire.
     * <p>
     * The assertions are on the epoch of the record that was actually sent - the returned record number and
     * the epoch bits in the datagram - and on which peer can still read it, not on the field. A field
     * assertion would pass even if the send path had picked up the derived epoch regardless.
     * </p>
     * <p>
     * Mutations this test is built to catch: have {@code derivePendingWriteEpoch} assign {@code writeEpoch}
     * (i.e. behave like {@code enablePendingEpochWrite}) and the pre-install assertions fail; make
     * {@code installPendingWriteEpoch} merely clear the slot without assigning {@code writeEpoch} and the
     * post-install assertions fail.
     * </p>
     */
    public void testDerivedWriteEpochIsNotSentUnderUntilInstalled() throws Exception
    {
        setUpPairWithRetainedEpochs();

        DTLSRecordLayer clientLayer = support.client.recordLayer;

        byte[] before = new byte[]{ 0x01, 0x02, 0x03, 0x04 };
        DTLSRecordNumber beforeDerive = clientLayer.sendReturningRecordNumber(before, 0, before.length);
        assertEquals(3, beforeDerive.getEpoch());

        DTLSEpoch derived = clientLayer.derivePendingWriteEpoch(createEpochCipher(support.client));
        assertEquals("the derived write epoch follows the write epoch, not the read epoch", 4,
            derived.getEpoch());
        assertEquals(4, clientLayer.getPendingWriteEpoch());

        // Deriving must not have changed what is sent
        byte[] held = new byte[]{ 0x05, 0x06, 0x07, 0x08 };
        DTLSRecordNumber whileHeld = clientLayer.sendReturningRecordNumber(held, 0, held.length);
        assertEquals("a derived write epoch must not be sent under until it is installed", 3,
            whileHeld.getEpoch());
        assertSentAtEpoch(3, 4, support.clientToServer.peekLast());

        // ... and the peer, whose read epoch is still 3, can still read it
        DTLSRecordLayer13TestSupport.receive(support.server, 200);
        byte[] received = DTLSRecordLayer13TestSupport.receive(support.server, 200);
        assertNotNull("the peer must still be able to read records sent while the epoch is only derived",
            received);
        assertTrue(Arrays.areEqual(held, received));

        // Installing it, and only installing it, changes the epoch on the wire
        assertSame(derived, clientLayer.installPendingWriteEpoch());
        assertEquals("installing clears the slot, so a later key update can derive its own epoch", -1,
            clientLayer.getPendingWriteEpoch());

        byte[] after = new byte[]{ 0x09, 0x0a, 0x0b, 0x0c };
        DTLSRecordNumber afterInstall = clientLayer.sendReturningRecordNumber(after, 0, after.length);
        assertEquals("an installed write epoch is the epoch records are sent under", 4,
            afterInstall.getEpoch());
        assertEquals("a newly installed epoch starts its own sequence number space", 0L,
            afterInstall.getSequenceNumber());
        assertSentAtEpoch(4, 3, support.clientToServer.peekLast());

        /*
         * 4 and 3 do not share the low 2 epoch bits, and the peer holds no epoch that does, so the record is
         * unreadable to it until its own read side is moved - which is a key update's job, not this task's.
         */
        assertNull("a record under the new epoch is not attributable to any epoch the peer holds",
            DTLSRecordLayer13TestSupport.receive(support.server, 100));
    }

    /**
     * Nothing has ever been sent under a derived-but-not-installed epoch, so there is nothing to retransmit
     * under it and {@link DTLSRecordLayer#sendHandshakeRecordAtEpoch(int, byte[], int, int)} must not resolve
     * it. Once installed it resolves like any write epoch.
     * <p>
     * Mutation this test is built to catch: add {@code pendingWriteEpoch} to {@code getEpochForRetransmit}
     * and the first half fails.
     * </p>
     */
    public void testDerivedWriteEpochIsNotResolvedForSendingUntilInstalled() throws Exception
    {
        setUpPairWithRetainedEpochs();

        DTLSRecordLayer clientLayer = support.client.recordLayer;
        clientLayer.derivePendingWriteEpoch(createEpochCipher(support.client));

        byte[] body = new byte[]{ 0x14, 0x00, 0x00, 0x00 };
        try
        {
            clientLayer.sendHandshakeRecordAtEpoch(4, body, 0, body.length);
            fail("expected a send at a derived-but-not-installed epoch to be refused");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.internal_error, e.getAlertDescription());
        }
        assertTrue("nothing may reach the wire under an epoch that is only derived",
            support.clientToServer.datagrams.isEmpty());

        clientLayer.installPendingWriteEpoch();

        DTLSRecordNumber recordNumber = clientLayer.sendHandshakeRecordAtEpoch(4, body, 0, body.length);
        assertNotNull(recordNumber);
        assertEquals(4, recordNumber.getEpoch());
        assertSentAtEpoch(4, 3, support.clientToServer.peekLast());
    }

    /**
     * The read side is untouched by either step, and the write epoch number is derived from the write epoch
     * alone. That is the whole reason for a field separate from {@code pendingEpoch}: after the handshake the
     * two directions advance on separate key updates, so one shared "next epoch" number is wrong.
     * <p>
     * Mutation this test is built to catch: derive the number from {@code readEpoch.getEpoch() + 1} and the
     * second derivation yields 4 again instead of 5.
     * </p>
     */
    public void testDerivedWriteEpochNumberIsIndependentOfTheReadEpoch() throws Exception
    {
        setUpPairWithRetainedEpochs();

        DTLSRecordLayer clientLayer = support.client.recordLayer;

        int[] beforeEpochs = epochNumbers(clientLayer);

        assertEquals(4, clientLayer.derivePendingWriteEpoch(createEpochCipher(support.client)).getEpoch());
        assertEquals("deriving a write epoch must not move the read side", 3, clientLayer.getReadEpoch());
        assertEquals("deriving a write epoch is not the handshake's pending epoch", -1,
            clientLayer.getPendingEpoch());
        assertTrue("deriving a write epoch must not alter the live read epochs",
            Arrays.areEqual(beforeEpochs, epochNumbers(clientLayer)));

        clientLayer.installPendingWriteEpoch();
        assertEquals("installing a write epoch must not move the read side", 3, clientLayer.getReadEpoch());
        assertEquals(-1, clientLayer.getPendingEpoch());
        assertTrue("installing a write epoch must not alter the live read epochs",
            Arrays.areEqual(beforeEpochs, epochNumbers(clientLayer)));

        assertEquals("the write side advances again from the write epoch, with the read epoch still at 3", 5,
            clientLayer.derivePendingWriteEpoch(createEpochCipher(support.client)).getEpoch());
        assertEquals(3, clientLayer.getReadEpoch());
    }

    /**
     * RFC 9147 5.8.4 forbids a second key update while one is still unacknowledged, so a second derivation
     * while one epoch is held is a bug on this side. Refusing it rather than overwriting matters because the
     * held epoch may already have been installed-and-sent-under by the time the mistake is noticed.
     */
    public void testAtMostOneDerivedWriteEpoch() throws Exception
    {
        setUpPairWithRetainedEpochs();

        DTLSRecordLayer clientLayer = support.client.recordLayer;

        DTLSEpoch derived = clientLayer.derivePendingWriteEpoch(createEpochCipher(support.client));

        try
        {
            clientLayer.derivePendingWriteEpoch(createEpochCipher(support.client));
            fail("expected a second derived write epoch to be refused");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        assertEquals(4, clientLayer.getPendingWriteEpoch());
        assertSame("the refused derivation must not have replaced the held epoch", derived,
            clientLayer.installPendingWriteEpoch());
    }

    public void testInstallPendingWriteEpochRequiresADerivedEpoch() throws Exception
    {
        setUpPairWithRetainedEpochs();

        DTLSRecordLayer clientLayer = support.client.recordLayer;
        assertEquals(-1, clientLayer.getPendingWriteEpoch());

        try
        {
            clientLayer.installPendingWriteEpoch();
            fail("expected installing with no derived write epoch to be refused");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        byte[] data = new byte[]{ 0x01, 0x02, 0x03, 0x04 };
        assertEquals("a refused install must not have moved the write epoch", 3,
            clientLayer.sendReturningRecordNumber(data, 0, data.length).getEpoch());
    }

    public void testDerivePendingWriteEpochRejectsNull() throws Exception
    {
        setUpPairWithRetainedEpochs();

        try
        {
            support.client.recordLayer.derivePendingWriteEpoch(null);
            fail("expected a null cipher to be refused");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public void testRetainReadEpochRejectsNull() throws Exception
    {
        setUpPairWithRetainedEpochs();

        try
        {
            support.client.recordLayer.retainReadEpoch(null);
            fail("expected a null retained read epoch to be refused");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }
}
